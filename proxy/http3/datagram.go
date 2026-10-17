package http3

import (
	gonet "net"
	"sync"

	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	"github.com/exclavenetwork/exclave-core/v5/common/net"
)

var (
	_ buf.Writer = (*datagramReaderWriter)(nil)
	_ buf.Reader = (*datagramReaderWriter)(nil)
)

type datagramReaderWriter struct {
	conn     net.Conn
	dest     net.Destination
	connLock sync.Mutex
	connMap  map[net.Destination]net.Conn
	dial     func(net.Destination) (net.Conn, error)
	packetCh chan *packet
	closed   chan struct{}
}

func newDatagramReaderWriter(conn net.Conn, dest net.Destination, dial func(net.Destination) (net.Conn, error)) *datagramReaderWriter {
	rw := &datagramReaderWriter{
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

func (rw *datagramReaderWriter) close() {
	close(rw.closed)
	rw.connLock.Lock()
	for dest, conn := range rw.connMap {
		delete(rw.connMap, dest)
		conn.Close()
	}
	rw.connLock.Unlock()
}

func (r *datagramReaderWriter) readLoop(conn net.Conn, dest net.Destination) {
loop:
	for {
		packet := &packet{}
		b := buf.New()
		b.Resize(0, buf.Size)
		n, err := conn.Read(b.Bytes())
		if err != nil {
			b.Release()
			packet.err = err
			r.packetCh <- packet
			break
		}
		b.Resize(0, int32(n))
		contextID, _, err := readVarint(b)
		if err != nil {
			b.Release()
			packet.err = err
			r.packetCh <- packet
			break
		}
		if contextID != 0x00 {
			b.Release()
			continue
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

func (r *datagramReaderWriter) ReadMultiBuffer() (buf.MultiBuffer, error) {
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

func (w *datagramReaderWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
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
		payload := buf.NewWithSize(1 + b.Len())
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
