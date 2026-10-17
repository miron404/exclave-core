package connectip

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type HTTP1ClientConn struct {
	conn net.Conn
}

func NewHTTP1ClientConn(conn net.Conn) *HTTP1ClientConn {
	return &HTTP1ClientConn{conn: conn}
}

func (c *HTTP1ClientConn) Dial(req *Request) (*Conn, *http.Response, error) {
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
	r := httpReq.Clone(streamCtx)
	err := r.Write(c.conn)
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("connect-ip: failed to send request: %w", err)
	}
	reader := bufio.NewReader(c.conn)
	rsp, err := http.ReadResponse(reader, r)
	if !stop() {
		if err == nil {
			rsp.Body.Close()
		}
		err = context.Cause(ctx)
	}
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("connect-ip: failed to read response: %w", err)
	}
	if rsp.StatusCode != http.StatusSwitchingProtocols {
		cancel()
		rsp.Body.Close()
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode)
	}
	if !strings.EqualFold(rsp.Header.Get("Connection"), "Upgrade") {
		cancel()
		rsp.Body.Close()
		return nil, nil, fmt.Errorf("connect-ip: invalid response \"Connection\" header")
	}
	if rsp.Header.Get("Upgrade") != requestProtocol {
		cancel()
		rsp.Body.Close()
		return nil, nil, fmt.Errorf("connect-ip: invalid response \"Upgrade\" header")
	}
	str := &http1Conn{
		conn:   c.conn,
		reader: reader,
		rsp:    rsp.Body,
		cancel: cancel,
	}
	return newProxiedConn(str, false), rsp, nil
}

type http1Conn struct {
	conn      net.Conn
	reader    *bufio.Reader
	rsp       io.Closer
	cancel    context.CancelFunc
	closeOnce sync.Once
	closeErr  error
}

func (c *http1Conn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *http1Conn) ReadByte() (byte, error) {
	return c.reader.ReadByte()
}

func (c *http1Conn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *http1Conn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		c.rsp.Close()
		c.closeErr = c.conn.Close()
	})
	return c.closeErr
}

func (c *http1Conn) CancelRead(_ quic.StreamErrorCode) {
	c.Close()
}

func (c *http1Conn) CancelWrite(_ quic.StreamErrorCode) {
	c.Close()
}

func (c *http1Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
