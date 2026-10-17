/*
Copyright 2024 Marten Seemann

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// https://github.com/quic-go/connect-ip-go

package connectip

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type ClientConn struct {
	clientConn *http3.ClientConn
}

func NewClientConn(conn *http3.ClientConn) *ClientConn {
	return &ClientConn{clientConn: conn}
}

func (c *ClientConn) Dial(req *Request) (*Conn, *http.Response, error) {
	httpReq := req.httpRequest()
	if httpReq.URL == nil {
		return nil, nil, errors.New("connect-ip: request URL is nil")
	}
	if httpReq.Host == "" && httpReq.URL.Host == "" {
		return nil, nil, errors.New("connect-ip: request needs a host")
	}

	select {
	case <-httpReq.Context().Done():
		return nil, nil, context.Cause(httpReq.Context())
	case <-c.clientConn.Context().Done():
		return nil, nil, context.Cause(c.clientConn.Context())
	case <-c.clientConn.ReceivedSettings():
	}

	settings := c.clientConn.Settings()
	if !settings.EnableExtendedConnect {
		return nil, nil, errors.New("connect-ip: server didn't enable Extended CONNECT")
	}

	rstr, err := c.clientConn.OpenRequestStream(httpReq.Context())
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to open request stream: %w", err)
	}
	var keepStream bool
	defer func() {
		if !keepStream {
			rstr.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
			rstr.CancelWrite(quic.StreamErrorCode(http3.ErrCodeNoError))
		}
	}()
	if err := rstr.SendRequestHeader(httpReq); err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to send request: %w", err)
	}
	rsp, err := rstr.ReadResponse()
	if err != nil {
		return nil, nil, fmt.Errorf("connect-ip: failed to read response: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode)
	}
	keepStream = true
	return newProxiedConn(rstr, settings.EnableDatagrams), rsp, nil
}
