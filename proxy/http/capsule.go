package http

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"math"
	gonet "net"
	"sync"

	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	"github.com/exclavenetwork/exclave-core/v5/common/net"
)

func varintLen(v uint64) int {
	switch {
	case v < 1<<6:
		return 1
	case v < 1<<14:
		return 2
	case v < 1<<30:
		return 4
	default:
		return 8
	}
}

var (
	_ buf.Writer = (*uotReaderWriter)(nil)
	_ buf.Reader = (*uotReaderWriter)(nil)
)

type packet struct {
	mb  buf.MultiBuffer
	err error
}

// uotReaderWriter carries UDP over CONNECT-UDP tunnels, one per destination:
// the tunnel the flow was opened with, and one more for each other
// destination it sends to, so that the mapping is address and port
// dependent.
type uotReaderWriter struct {
	conn      net.Conn
	dest      net.Destination
	connLock  sync.Mutex
	connMap   map[net.Destination]net.Conn
	dial      func(net.Destination) (net.Conn, []byte, error)
	packetCh  chan *packet
	closed    chan struct{}
	closeOnce sync.Once
	pending   []byte
}

// newUoTReaderWriter tunnels the flow over conn, the tunnel to dest. leftover
// is what was read past the response headers along with them, which belongs
// to the capsule stream too, and dial opens a tunnel to another destination
// in the same way.
func newUoTReaderWriter(conn net.Conn, dest net.Destination, leftover []byte, dial func(net.Destination) (net.Conn, []byte, error)) *uotReaderWriter {
	rw := &uotReaderWriter{
		conn:     conn,
		dest:     dest,
		connMap:  make(map[net.Destination]net.Conn),
		dial:     dial,
		packetCh: make(chan *packet, 16),
		closed:   make(chan struct{}),
	}
	go rw.readLoop(conn, dest, leftover)
	return rw
}

func (rw *uotReaderWriter) close() {
	rw.closeOnce.Do(func() {
		close(rw.closed)
		rw.connLock.Lock()
		for dest, conn := range rw.connMap {
			delete(rw.connMap, dest)
			conn.Close()
		}
		rw.connLock.Unlock()
	})
}

// send hands p to the reader, unless the flow has closed and nobody will
// read it.
func (rw *uotReaderWriter) send(p *packet) bool {
	select {
	case rw.packetCh <- p:
		return true
	case <-rw.closed:
		return false
	}
}

func (rw *uotReaderWriter) readLoop(conn net.Conn, dest net.Destination, leftover []byte) {
	r := newCapsuleReader(conn, leftover)
	for {
		b, err := r.readDatagram()
		if err != nil {
			if dest == rw.dest {
				// The flow's own tunnel ending ends the flow.
				rw.send(&packet{err: err})
				return
			}
			// Another destination's tunnel ending only loses that
			// destination, until something is sent there again.
			rw.drop(dest, conn)
			return
		}
		b.Endpoint = &net.Destination{
			Address: dest.Address,
			Port:    dest.Port,
			Network: net.Network_UDP,
		}
		if !rw.send(&packet{mb: buf.MultiBuffer{b}}) {
			b.Release()
			return
		}
	}
}

// drop forgets the tunnel to dest, if conn is still the one held for it.
func (rw *uotReaderWriter) drop(dest net.Destination, conn net.Conn) {
	rw.connLock.Lock()
	if rw.connMap[dest] == conn {
		delete(rw.connMap, dest)
	}
	rw.connLock.Unlock()
	conn.Close()
}

func (rw *uotReaderWriter) ReadMultiBuffer() (buf.MultiBuffer, error) {
	select {
	case packet := <-rw.packetCh:
		return packet.mb, packet.err
	case <-rw.closed:
		for {
			select {
			case packet := <-rw.packetCh:
				buf.ReleaseMulti(packet.mb)
			default:
				return nil, gonet.ErrClosed
			}
		}
	}
}

// connFor returns the tunnel to dest, opening one if there is none.
func (rw *uotReaderWriter) connFor(dest net.Destination) (net.Conn, error) {
	if dest == rw.dest {
		return rw.conn, nil
	}
	rw.connLock.Lock()
	conn, ok := rw.connMap[dest]
	rw.connLock.Unlock()
	if ok {
		return conn, nil
	}
	conn, leftover, err := rw.dial(dest)
	if err != nil {
		return nil, err
	}
	rw.connLock.Lock()
	select {
	case <-rw.closed:
		rw.connLock.Unlock()
		conn.Close()
		return nil, gonet.ErrClosed
	default:
	}
	rw.connMap[dest] = conn
	rw.connLock.Unlock()
	go rw.readLoop(conn, dest, leftover)
	return conn, nil
}

// WriteMultiBuffer sends the datagrams in mb as capsules, with each run of
// datagrams to the same destination in one write rather than one write
// each, which over TLS is a record and a system call per datagram.
func (rw *uotReaderWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	var conn net.Conn
	var connDest net.Destination
	chosen := false
	flush := func() error {
		if conn == nil || len(rw.pending) == 0 {
			return nil
		}
		_, err := conn.Write(rw.pending)
		rw.pending = rw.pending[:0]
		if err != nil && connDest != rw.dest {
			// As when it fails to read: only that destination is lost.
			rw.drop(connDest, conn)
			return nil
		}
		return err
	}
	for _, b := range mb {
		if b == nil {
			continue
		}
		dest := rw.dest
		if b.Endpoint != nil {
			dest = *b.Endpoint
		}
		if !chosen || dest != connDest {
			if err := flush(); err != nil {
				return err
			}
			var err error
			conn, err = rw.connFor(dest)
			if err != nil {
				conn = nil
			}
			connDest = dest
			chosen = true
		}
		if conn == nil {
			// No tunnel to there: the datagram is lost, as it would be on
			// a path that could not carry it, and so are the rest of this
			// run rather than each trying to open one again.
			continue
		}
		rw.pending = appendDatagramCapsule(rw.pending, b.Bytes())
	}
	err := flush()
	if cap(rw.pending) > 64<<10 {
		// One huge batch should not pin its buffer for the life of the flow.
		rw.pending = nil
	}
	return err
}

// appendDatagramCapsule appends payload as an HTTP Datagram capsule for
// context 0, the UDP payload context of RFC 9298.
func appendDatagramCapsule(b []byte, payload []byte) []byte {
	// Capsule Type, Capsule Length, Context ID, UDP Proxying Payload
	b = append(b, 0x00)
	b = appendVarint(b, uint64(1+len(payload)))
	b = append(b, 0x00)
	return append(b, payload...)
}

func appendVarint(b []byte, v uint64) []byte {
	switch varintLen(v) {
	case 1:
		return append(b, byte(v))
	case 2:
		return binary.BigEndian.AppendUint16(b, uint16(v)|0x4000)
	case 4:
		return binary.BigEndian.AppendUint32(b, uint32(v)|0x80000000)
	default:
		return binary.BigEndian.AppendUint64(b, v|0xc000000000000000)
	}
}

type capsuleReader struct {
	r *bufio.Reader
}

// newCapsuleReader reads datagram capsules from conn, starting with
// leftover.
func newCapsuleReader(conn io.Reader, leftover []byte) *capsuleReader {
	if len(leftover) > 0 {
		conn = io.MultiReader(bytes.NewReader(leftover), conn)
	}
	// Buffered, so that a capsule header costs no read of its own on the
	// connection, one byte at a time.
	return &capsuleReader{r: bufio.NewReaderSize(conn, 16<<10)}
}

// readDatagram returns the payload of the next UDP datagram.
func (r *capsuleReader) readDatagram() (*buf.Buffer, error) {
	for {
		capsuleType, _, err := r.readVarint()
		if err != nil {
			return nil, err
		}
		capsuleLength, _, err := r.readVarint()
		if err != nil {
			return nil, err
		}
		if capsuleLength > math.MaxInt32 {
			return nil, newError("invalid capsule length")
		}
		if capsuleType != 0 {
			// RFC 9297: an unknown capsule is skipped, not an error.
			if err := r.discard(int64(capsuleLength)); err != nil {
				return nil, err
			}
			continue
		}
		contextID, contextIDLength, err := r.readVarint()
		if err != nil {
			return nil, err
		}
		payloadLength := int32(capsuleLength) - int32(contextIDLength)
		if payloadLength < 0 {
			return nil, newError("invalid payload length")
		}
		if contextID != 0 {
			// RFC 9298: a datagram for a context this client never set up
			// is dropped.
			if err := r.discard(int64(payloadLength)); err != nil {
				return nil, err
			}
			continue
		}
		b := buf.NewWithSize(payloadLength)
		if _, err = b.ReadFullFrom(r.r, payloadLength); err != nil {
			b.Release()
			return nil, err
		}
		return b, nil
	}
}

func (r *capsuleReader) discard(n int64) error {
	_, err := io.CopyN(io.Discard, r.r, n)
	return err
}

func (r *capsuleReader) readVarint() (uint64, int, error) {
	first, err := r.r.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	length := 1 << (first >> 6)
	value := uint64(first & 0x3f)
	for i := 1; i < length; i++ {
		b, err := r.r.ReadByte()
		if err != nil {
			return 0, 0, err
		}
		value = value<<8 | uint64(b)
	}
	return value, length, nil
}
