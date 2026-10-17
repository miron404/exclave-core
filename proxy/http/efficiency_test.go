package http

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	"github.com/exclavenetwork/exclave-core/v5/common/net"
)

type countingWriter struct {
	bytes.Buffer
	writes int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes++
	return w.Buffer.Write(p)
}

func bufferOf(data []byte) *buf.Buffer {
	b := buf.New()
	b.Write(data)
	return b
}

// A MultiBuffer goes out in as few writes as fit a TLS record, in order.
func TestCoalescingWriterGathersBuffers(t *testing.T) {
	var want []byte
	var mb buf.MultiBuffer
	for i := range 5 {
		data := bytes.Repeat([]byte{byte(i)}, 8000)
		want = append(want, data...)
		mb = append(mb, bufferOf(data))
	}
	w := &countingWriter{}
	if err := newCoalescingWriter(w).WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.Bytes(), want) {
		t.Fatal("the stream came out changed")
	}
	if w.writes != 3 {
		t.Fatalf("40000 bytes took %d writes, want 3", w.writes)
	}
}

// Writes made while the transport is busy go out in one read; the transport
// closing the body releases a waiting writer; closing it from the tunnel's
// side lets the transport drain it first.
func TestStreamBody(t *testing.T) {
	b := newStreamBody()
	for i := range 4 {
		if _, err := b.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	p := make([]byte, 64)
	if n, _ := b.Read(p); n != 4 {
		t.Fatalf("read %d bytes, want the 4 written", n)
	}

	big := make([]byte, streamBodyLimit)
	if _, err := b.Write(big); err != nil {
		t.Fatal(err)
	}
	blocked := make(chan error, 1)
	go func() { _, err := b.Write([]byte{1}); blocked <- err }()
	select {
	case <-blocked:
		t.Fatal("a full body accepted another write")
	case <-time.After(50 * time.Millisecond):
	}
	_ = b.Close()
	if err := <-blocked; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("closing the body did not release the writer: ", err)
	}

	b = newStreamBody()
	_, _ = b.Write([]byte("tail"))
	_ = b.CloseWrite()
	got, err := io.ReadAll(b)
	if err != nil || string(got) != "tail" {
		t.Fatalf("drained %q, %v", got, err)
	}
}

func capsule(capsuleType uint64, value []byte) []byte {
	out := appendVarint(nil, capsuleType)
	out = appendVarint(out, uint64(len(value)))
	return append(out, value...)
}

// Capsules of an unknown type and datagrams for another context are skipped
// rather than ending the session, and bytes read past the response headers
// are parsed as part of the capsule stream.
func TestCapsuleReader(t *testing.T) {
	stream := capsule(0, append([]byte{0}, []byte("first")...))
	stream = append(stream, capsule(0x2a, []byte("unknown capsule"))...)
	stream = append(stream, capsule(0, append([]byte{7}, []byte("other context")...))...)
	stream = append(stream, capsule(0, append([]byte{0}, []byte("second")...))...)

	// The first few bytes arrive with the response headers.
	r := newCapsuleReader(bytes.NewReader(stream[5:]), stream[:5])
	for _, want := range []string{"first", "second"} {
		b, err := r.readDatagram()
		if err != nil {
			t.Fatal(err)
		}
		if got := b.String(); got != want {
			t.Fatalf("read %q, want %q", got, want)
		}
		b.Release()
	}
	if _, err := r.readDatagram(); !errors.Is(err, io.EOF) {
		t.Fatal("expected the end of the stream, got ", err)
	}
}

// tunnelConn stands for a CONNECT-UDP tunnel: it records what is written,
// and its reads wait until it is closed.
type tunnelConn struct {
	net.Conn
	w      countingWriter
	closed chan struct{}
	once   sync.Once
}

func newTunnelConn() *tunnelConn { return &tunnelConn{closed: make(chan struct{})} }

func (c *tunnelConn) Write(p []byte) (int, error) { return c.w.Write(p) }

func (c *tunnelConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *tunnelConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func datagramTo(dest net.Destination, size int, tag byte) *buf.Buffer {
	b := buf.NewWithSize(int32(size))
	b.Extend(int32(size))
	b.Bytes()[0] = tag
	b.Endpoint = &dest
	return b
}

// Every datagram in a MultiBuffer goes out in one write, and reads back as
// it was sent.
func TestUoTWriterBatches(t *testing.T) {
	dest := net.UDPDestination(net.ParseAddress("192.0.2.1"), 53)
	conn := newTunnelConn()
	rw := newUoTReaderWriter(conn, dest, nil, func(net.Destination) (net.Conn, []byte, error) {
		t.Fatal("dialed for the flow's own destination")
		return nil, nil, nil
	})
	defer rw.close()
	sizes := []int{1, 63, 64, 1400, 16383, 16384}
	var mb buf.MultiBuffer
	for i, size := range sizes {
		mb = append(mb, datagramTo(dest, size, byte(i)))
	}
	if err := rw.WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}
	if conn.w.writes != 1 {
		t.Fatalf("%d datagrams took %d writes, want 1", len(sizes), conn.w.writes)
	}
	r := newCapsuleReader(bytes.NewReader(conn.w.Bytes()), nil)
	for i, size := range sizes {
		got, err := r.readDatagram()
		if err != nil {
			t.Fatal(err)
		}
		if got.Len() != int32(size) || got.Byte(0) != byte(i) {
			t.Fatalf("datagram %d came back as %d bytes", i, got.Len())
		}
		got.Release()
	}
}

// Datagrams to another destination go through a tunnel of their own,
// opened once, and a run of them still takes one write. That tunnel ending
// loses only that destination: the next datagram there opens a new one.
func TestUoTOtherDestinations(t *testing.T) {
	a := net.UDPDestination(net.ParseAddress("192.0.2.1"), 53)
	b := net.UDPDestination(net.ParseAddress("192.0.2.2"), 443)
	connA := newTunnelConn()
	var dialed []*tunnelConn
	rw := newUoTReaderWriter(connA, a, nil, func(dest net.Destination) (net.Conn, []byte, error) {
		if dest != b {
			t.Fatal("dialed ", dest)
		}
		conn := newTunnelConn()
		dialed = append(dialed, conn)
		return conn, nil, nil
	})
	defer rw.close()
	mb := buf.MultiBuffer{datagramTo(a, 10, 1), datagramTo(a, 10, 2), datagramTo(b, 10, 3), datagramTo(b, 10, 4), datagramTo(a, 10, 5)}
	if err := rw.WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}
	if len(dialed) != 1 {
		t.Fatalf("opened %d tunnels to the other destination, want 1", len(dialed))
	}
	if connA.w.writes != 2 || dialed[0].w.writes != 1 {
		t.Fatalf("writes: %d to the flow's tunnel, want 2; %d to the other, want 1", connA.w.writes, dialed[0].w.writes)
	}

	dialed[0].Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rw.connLock.Lock()
		_, held := rw.connMap[b]
		rw.connLock.Unlock()
		if !held {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the ended tunnel is still held")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case p := <-rw.packetCh:
		t.Fatal("the other tunnel ending reached the flow: ", p.err)
	default:
	}
	if err := rw.WriteMultiBuffer(buf.MultiBuffer{datagramTo(b, 10, 6)}); err != nil {
		t.Fatal(err)
	}
	if len(dialed) != 2 || dialed[1].w.writes != 1 {
		t.Fatal("no new tunnel for the destination whose tunnel ended")
	}
}
