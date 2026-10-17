package http3

import (
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

type uotReaderWriter struct {
	conn     net.Conn
	dest     net.Destination
	connLock sync.Mutex
	connMap  map[net.Destination]net.Conn
	dial     func(net.Destination) (net.Conn, error)
	packetCh chan *packet
	closed   chan struct{}
}

func newUoTReaderWriter(conn net.Conn, dest net.Destination, dial func(net.Destination) (net.Conn, error)) *uotReaderWriter {
	rw := &uotReaderWriter{
		conn:     conn,
		dest:     dest,
		connMap:  make(map[net.Destination]net.Conn),
		dial:     dial,
		packetCh: make(chan *packet, 16),
		closed:   make(chan struct{}),
	}
	go rw.readLoop(conn, dest)
	return rw
}

func (rw *uotReaderWriter) close() {
	close(rw.closed)
	rw.connLock.Lock()
	for dest, conn := range rw.connMap {
		delete(rw.connMap, dest)
		conn.Close()
	}
	rw.connLock.Unlock()
}

func (r *uotReaderWriter) readLoop(conn net.Conn, dest net.Destination) {
loop:
	for {
		packet := &packet{}
		capsuleType, _, err := readVarint(conn)
		if err != nil {
			packet.err = err
			r.packetCh <- packet
			break
		}
		capsuleLength, _, err := readVarint(conn)
		if err != nil {
			packet.err = err
			r.packetCh <- packet
			break
		}
		if capsuleLength > math.MaxInt32 {
			packet.err = newError("invalid capsule length")
			r.packetCh <- packet
			break
		}
		if capsuleType != 0 {
			_, err = io.CopyN(io.Discard, conn, int64(capsuleLength))
			if err != nil {
				packet.err = err
				r.packetCh <- packet
				break
			}
			continue
		}
		contextID, contextIDLength, err := readVarint(conn)
		if err != nil {
			packet.err = err
			r.packetCh <- packet
			break
		}
		payloadLength := int32(capsuleLength) - int32(contextIDLength)
		if payloadLength < 0 {
			packet.err = newError("invalid payload length")
			r.packetCh <- packet
			break
		}
		if contextID != 0 {
			_, err = io.CopyN(io.Discard, conn, int64(payloadLength))
			if err != nil {
				packet.err = err
				r.packetCh <- packet
				break
			}
			continue
		}
		b := buf.NewWithSize(payloadLength)
		if _, err = b.ReadFullFrom(conn, payloadLength); err != nil {
			b.Release()
			packet.err = err
			r.packetCh <- packet
			break
		}
		select {
		case <-r.closed:
			b.Release()
			break loop
		default:
			b.Endpoint = &net.Destination{
				Address: dest.Address,
				Port:    dest.Port,
				Network: net.Network_UDP,
			}
			packet.mb = buf.MultiBuffer{b}
			r.packetCh <- packet
		}
	}
	if dest != r.dest {
		r.connLock.Lock()
		delete(r.connMap, dest)
		r.connLock.Unlock()
	}
}

func (r *uotReaderWriter) ReadMultiBuffer() (buf.MultiBuffer, error) {
	select {
	case packet := <-r.packetCh:
		return packet.mb, packet.err
	case <-r.closed:
		for packet := range r.packetCh {
			if packet.mb != nil {
				buf.ReleaseMulti(packet.mb)
			}
		}
		return nil, gonet.ErrClosed
	}
}

func readVarint(reader io.Reader) (uint64, int, error) {
	var b [1]byte
	_, err := io.ReadFull(reader, b[:])
	if err != nil {
		return 0, 0, err
	}
	length := 1 << (b[0] >> 6)
	value := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		_, err = io.ReadFull(reader, b[:])
		if err != nil {
			return 0, 0, err
		}
		value = value<<8 | uint64(b[0])
	}
	return value, length, nil
}

func (w *uotReaderWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		dest := w.dest
		if b.Endpoint != nil {
			dest = *b.Endpoint
		}
		var conn net.Conn
		if dest == w.dest {
			conn = w.conn
		} else {
			w.connLock.Lock()
			cacheConn, ok := w.connMap[dest]
			w.connLock.Unlock()
			if ok {
				conn = cacheConn
			} else {
				newConn, err := w.dial(dest)
				if err != nil {
					continue
				}
				select {
				case <-w.closed:
					newConn.Close()
					return gonet.ErrClosed
				default:
					go w.readLoop(newConn, dest)
				}
				w.connLock.Lock()
				w.connMap[dest] = newConn
				w.connLock.Unlock()
				conn = newConn
			}
		}
		capsuleLength := uint64(1 + b.Len())
		payload := buf.NewWithSize(1 + int32(varintLen(capsuleLength)) + 1 + b.Len())
		// Capsule Type
		payload.WriteByte(0x00)
		// Capsule Length
		switch varintLen(capsuleLength) {
		case 1:
			payload.WriteByte(byte(capsuleLength))
		case 2:
			var v [2]byte
			binary.BigEndian.PutUint16(v[:], uint16(capsuleLength)|0x4000)
			payload.Write(v[:])
		case 4:
			var v [4]byte
			binary.BigEndian.PutUint32(v[:], uint32(capsuleLength)|0x80000000)
			payload.Write(v[:])
		default:
			var v [8]byte
			binary.BigEndian.PutUint64(v[:], capsuleLength|0xc000000000000000)
			payload.Write(v[:])
		}
		// Capsule Value
		payload.WriteByte(0x00)  // Context ID
		payload.Write(b.Bytes()) // UDP Proxying Payload
		_, err := conn.Write(payload.Bytes())
		payload.Release()
		if err != nil {
			return err
		}
	}
	return nil
}
