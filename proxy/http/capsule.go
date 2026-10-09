package http

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"math"

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
	_ buf.Writer = (*uotWriter)(nil)
	_ buf.Reader = (*uotReader)(nil)
)

type uotReader struct {
	r *bufio.Reader
}

// newUoTReader reads datagram capsules from conn. leftover is what was read
// past the response headers along with them, which belongs to the capsule
// stream too.
func newUoTReader(conn io.Reader, leftover []byte) *uotReader {
	if len(leftover) > 0 {
		conn = io.MultiReader(bytes.NewReader(leftover), conn)
	}
	// Buffered, so that a capsule header costs no read of its own on the
	// connection, one byte at a time as it used to.
	return &uotReader{r: bufio.NewReaderSize(conn, 16<<10)}
}

func (r *uotReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
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
		return buf.MultiBuffer{b}, nil
	}
}

func (r *uotReader) discard(n int64) error {
	_, err := io.CopyN(io.Discard, r.r, n)
	return err
}

func (r *uotReader) readVarint() (uint64, int, error) {
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

type uotWriter struct {
	conn    net.Conn
	dest    net.Destination
	pending []byte
}

func newUoTWriter(conn net.Conn, dest net.Destination) *uotWriter {
	return &uotWriter{
		conn: conn,
		dest: dest,
	}
}

// WriteMultiBuffer sends every datagram in mb as capsules in one write,
// rather than one write each, which over TLS is a record and a system call
// per datagram.
func (w *uotWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	w.pending = w.pending[:0]
	for _, b := range mb {
		if b == nil {
			continue
		}
		if b.Endpoint != nil && *b.Endpoint != w.dest {
			newError("CONNECT-UDP can not have different destination addresses").AtDebug().WriteToLog()
			continue
		}
		capsuleLength := uint64(1 + b.Len())
		// Capsule Type, Capsule Length, Context ID, UDP Proxying Payload
		w.pending = append(w.pending, 0x00)
		w.pending = appendVarint(w.pending, capsuleLength)
		w.pending = append(w.pending, 0x00)
		w.pending = append(w.pending, b.Bytes()...)
	}
	if len(w.pending) == 0 {
		return nil
	}
	_, err := w.conn.Write(w.pending)
	if cap(w.pending) > 64<<10 {
		// One huge batch should not pin its buffer for the life of the flow.
		w.pending = nil
	}
	return err
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
