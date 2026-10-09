package http

import (
	"io"
	"sync"
)

// streamBodyLimit is how much may wait for the HTTP/2 transport before a
// writer is held back: a little over one frame at the default frame size.
const streamBodyLimit = 16<<10 + 2048

// streamBody is the request body a tunnel over an HTTP/2 proxy writes into.
//
// The HTTP/2 client writes one DATA frame, and flushes it to the connection,
// for every read it makes from a request body. Through an io.Pipe every read
// is exactly one write from the tunnel, however small, and the writer waits
// for it to be sent. Here writes gather while the transport is busy, and the
// next read takes all of them; a write made while the transport is idle still
// goes out at once.
type streamBody struct {
	mu       sync.Mutex
	readable *sync.Cond
	writable *sync.Cond
	pending  []byte
	// readErr is what the transport gets once pending is drained; writeErr is
	// what a writer gets once the body is closed either way.
	readErr, writeErr error
}

func newStreamBody() *streamBody {
	b := &streamBody{pending: make([]byte, 0, streamBodyLimit)}
	b.readable = sync.NewCond(&b.mu)
	b.writable = sync.NewCond(&b.mu)
	return b
}

// Write queues p, waiting while the queue is full. A write is always accepted
// into an empty queue, whatever its size.
func (b *streamBody) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.writeErr == nil && len(b.pending) > 0 && len(b.pending)+len(p) > streamBodyLimit {
		b.writable.Wait()
	}
	if b.writeErr != nil {
		return 0, b.writeErr
	}
	b.pending = append(b.pending, p...)
	b.readable.Signal()
	return len(p), nil
}

// Read hands the transport everything queued, up to len(p).
func (b *streamBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.pending) == 0 && b.readErr == nil {
		b.readable.Wait()
	}
	if len(b.pending) == 0 {
		return 0, b.readErr
	}
	n := copy(p, b.pending)
	b.pending = b.pending[:copy(b.pending, b.pending[n:])]
	b.writable.Broadcast()
	return n, nil
}

// Close is called by the transport when it is done with the body, and turns
// away every writer from then on.
func (b *streamBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.writeErr == nil {
		b.writeErr = io.ErrClosedPipe
	}
	if b.readErr == nil {
		b.readErr = io.ErrClosedPipe
	}
	b.pending = b.pending[:0]
	b.readable.Broadcast()
	b.writable.Broadcast()
	return nil
}

// CloseWrite ends the stream from the tunnel's side: the transport reads what
// is queued, then io.EOF.
func (b *streamBody) CloseWrite() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.writeErr == nil {
		b.writeErr = io.ErrClosedPipe
	}
	if b.readErr == nil {
		b.readErr = io.EOF
	}
	b.readable.Broadcast()
	b.writable.Broadcast()
	return nil
}
