package http

import (
	"io"

	"github.com/exclavenetwork/exclave-core/v5/common/buf"
)

// coalescedWriteSize is the most one write gathers: a full TLS record.
const coalescedWriteSize = 16 << 10

// coalescingWriter writes a MultiBuffer in as few writes as it fits, rather
// than one per buffer. Over TLS each write is a record and a system call of
// its own, and the buffers coming out of the core are 8 kB at most, so a
// stream through the proxy cost twice the records and calls it had to.
type coalescingWriter struct {
	w       io.Writer
	scratch []byte
}

func newCoalescingWriter(w io.Writer) *coalescingWriter {
	return &coalescingWriter{w: w}
}

func (w *coalescingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	if len(mb) == 1 {
		return writeAll(w.w, mb[0].Bytes())
	}
	if w.scratch == nil {
		w.scratch = make([]byte, 0, coalescedWriteSize)
	}
	pending := w.scratch[:0]
	for _, b := range mb {
		if b == nil {
			continue
		}
		data := b.Bytes()
		for len(data) > 0 {
			n := min(len(data), coalescedWriteSize-len(pending))
			pending = append(pending, data[:n]...)
			data = data[n:]
			if len(pending) == coalescedWriteSize {
				if err := writeAll(w.w, pending); err != nil {
					return err
				}
				pending = pending[:0]
			}
		}
	}
	if len(pending) > 0 {
		return writeAll(w.w, pending)
	}
	return nil
}

func writeAll(w io.Writer, p []byte) error {
	_, err := w.Write(p)
	return err
}
