// SPDX-License-Identifier: MPL-2.0

// https://github.com/XTLS/Xray-core/blob/c77a4d0e4932a53f3eeafafdfef877b56fd660ad/transport/internet/masque/http2.go

package connectip

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const maxStreamBuffer = 32 << 10

type HTTP2ClientConn struct {
	clientConn http.RoundTripper
}

func NewHTTP2ClientConn(clientConn http.RoundTripper) *HTTP2ClientConn {
	return &HTTP2ClientConn{clientConn: clientConn}
}

func (c *HTTP2ClientConn) Dial(req *Request) (*Conn, *http.Response, error) {
	httpReq := req.httpRequest()
	if httpReq.URL == nil {
		return nil, nil, errors.New("connect-ip: request URL is nil")
	}
	if httpReq.Host == "" && httpReq.URL.Host == "" {
		return nil, nil, errors.New("connect-ip: request needs a host")
	}

	ctx := httpReq.Context()
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, cancel)
	body := newStreamBuffer()
	r := httpReq.Clone(streamCtx)
	r.Body = body
	rsp, err := c.clientConn.RoundTrip(r)
	if !stop() {
		if err == nil {
			rsp.Body.Close()
		}
		err = context.Cause(ctx)
	}
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("connect-ip: failed to send request: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		cancel()
		rsp.Body.Close()
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode)
	}
	str := &http2Stream{
		reader: bufio.NewReader(rsp.Body),
		body:   body,
		rsp:    rsp.Body,
		cancel: cancel,
	}
	return newProxiedConn(str, false), rsp, nil
}

type http2Stream struct {
	reader    *bufio.Reader
	body      *streamBuffer
	rsp       io.Closer
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

func (s *http2Stream) Read(b []byte) (int, error) {
	return s.reader.Read(b)
}

func (s *http2Stream) ReadByte() (byte, error) {
	return s.reader.ReadByte()
}

func (s *http2Stream) Write(b []byte) (int, error) {
	return s.body.Write(b)
}

func (s *http2Stream) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		s.rsp.Close()
		s.closeErr = s.body.Close()
	})
	return s.closeErr
}

func (s *http2Stream) CancelRead(_ quic.StreamErrorCode) {
	s.Close()
}

func (s *http2Stream) CancelWrite(_ quic.StreamErrorCode) {
	s.Close()
}

func (s *http2Stream) SetWriteDeadline(t time.Time) error {
	return s.body.SetWriteDeadline(t)
}

type streamBuffer struct {
	mu       sync.Mutex
	cond     sync.Cond
	buf      []byte
	closed   bool
	err      error
	deadline time.Time
}

func newStreamBuffer() *streamBuffer {
	b := &streamBuffer{}
	b.cond.L = &b.mu
	return b
}

func (b *streamBuffer) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.buf) == 0 && !b.closed && b.err == nil {
		b.cond.Wait()
	}
	if b.err != nil {
		return 0, b.err
	}
	if len(b.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.buf)
	b.buf = b.buf[:copy(b.buf, b.buf[n:])]
	b.cond.Broadcast()
	return n, nil
}

func (b *streamBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		switch {
		case b.err != nil:
			return 0, b.err
		case b.closed:
			return 0, io.ErrClosedPipe
		case !b.deadline.IsZero() && !time.Now().Before(b.deadline):
			return 0, os.ErrDeadlineExceeded
		case len(b.buf) < maxStreamBuffer:
			b.buf = append(b.buf, p...)
			b.cond.Broadcast()
			return len(p), nil
		}
		b.cond.Wait()
	}
}

func (b *streamBuffer) Close() error {
	b.mu.Lock()
	b.closed = true
	b.cond.Broadcast()
	b.mu.Unlock()
	return nil
}

func (b *streamBuffer) CloseWithError(err error) {
	b.mu.Lock()
	if b.err == nil {
		b.err = err
		b.buf = nil
	}
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *streamBuffer) SetWriteDeadline(t time.Time) error {
	b.mu.Lock()
	b.deadline = t
	b.cond.Broadcast()
	b.mu.Unlock()
	if d := time.Until(t); d > 0 {
		time.AfterFunc(d, func() {
			b.mu.Lock()
			b.cond.Broadcast()
			b.mu.Unlock()
		})
	}
	return nil
}

type http2ResponseStream struct {
	reader     *bufio.Reader
	body       io.Closer
	w          io.Writer
	controller *http.ResponseController
}

func (s *http2ResponseStream) Read(b []byte) (int, error) {
	return s.reader.Read(b)
}

func (s *http2ResponseStream) ReadByte() (byte, error) {
	return s.reader.ReadByte()
}

func (s *http2ResponseStream) Write(b []byte) (int, error) {
	n, err := s.w.Write(b)
	if err == nil {
		err = s.controller.Flush()
	}
	return n, err
}

func (s *http2ResponseStream) Close() error {
	return s.body.Close()
}

func (s *http2ResponseStream) CancelRead(_ quic.StreamErrorCode) {
	s.body.Close()
}

func (s *http2ResponseStream) CancelWrite(_ quic.StreamErrorCode) {
	s.body.Close()
}

func (s *http2ResponseStream) SetWriteDeadline(t time.Time) error {
	return s.controller.SetWriteDeadline(t)
}
