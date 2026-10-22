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
	"net/http"
	"net/url"

	"github.com/quic-go/quic-go/http3"
)

const requestProtocol = "connect-ip"

var capsuleProtocolHeaderValue = "?1"

type Request struct {
	req *http.Request
}

func NewRequest(ctx context.Context, u *url.URL) (*Request, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    u,
		Host:   u.Host,
		Header: make(http.Header),
		Proto:  requestProtocol,
	}
	req.Header.Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	return &Request{req: req.WithContext(ctx)}, nil
}

func NewHTTP2Request(ctx context.Context, u *url.URL) (*Request, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    u,
		Host:   u.Host,
		Header: make(http.Header),
	}
	req.Header.Set(":protocol", requestProtocol)
	req.Header.Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	return &Request{req: req.WithContext(ctx)}, nil
}

func NewHTTP1Request(ctx context.Context, u *url.URL) (*Request, error) {
	req := &http.Request{
		Method: http.MethodGet,
		URL:    u,
		Host:   u.Host,
		Header: make(http.Header),
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", requestProtocol)
	req.Header.Set(http3.CapsuleProtocolHeader, capsuleProtocolHeaderValue)
	return &Request{req: req.WithContext(ctx)}, nil
}

func (r *Request) Header() http.Header {
	return r.req.Header
}

func (r *Request) httpRequest() *http.Request {
	return r.req
}
