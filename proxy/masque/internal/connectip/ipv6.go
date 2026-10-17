/*
Copyright 2024 Marten Seemann

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// https://github.com/quic-go/connect-ip-go

package connectip

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/net/ipv6"
)

const (
	ipProtoHopByHop = 0
	ipProtoRouting  = 43
	ipProtoFragment = 44
	ipProtoAH       = 51
	ipProtoDestOpts = 60
)

var errTruncatedExtensionHeader = errors.New("connect-ip: malformed datagram: truncated IPv6 extension header")

func validateIPv6PayloadLength(b []byte) error {
	if l := int(binary.BigEndian.Uint16(b[4:6])); ipv6.HeaderLen+l != len(b) {
		return fmt.Errorf("connect-ip: IPv6 payload length (%d) doesn't match packet size (%d)", l, len(b)-ipv6.HeaderLen)
	}
	return nil
}

func ipv6UpperLayerProtocol(b []byte) (uint8, []byte, error) {
	next := b[6]
	pos := ipv6.HeaderLen
	for {
		switch next {
		case ipProtoHopByHop, ipProtoRouting, ipProtoFragment, ipProtoAH, ipProtoDestOpts:
		default:
			return next, b[pos:], nil
		}
		if next == ipProtoHopByHop && pos != ipv6.HeaderLen {
			return 0, nil, errors.New("connect-ip: malformed datagram: misplaced Hop-by-Hop Options header")
		}
		if len(b) < pos+8 {
			return 0, nil, errTruncatedExtensionHeader
		}
		var hdrLen int
		switch next {
		case ipProtoFragment:
			if binary.BigEndian.Uint16(b[pos+2:pos+4])>>3 != 0 {
				return ipProtoFragment, nil, nil
			}
			hdrLen = 8
		case ipProtoAH:
			hdrLen = (int(b[pos+1]) + 2) * 4
		default:
			hdrLen = (int(b[pos+1]) + 1) * 8
		}
		if len(b) < pos+hdrLen {
			return 0, nil, errTruncatedExtensionHeader
		}
		next = b[pos]
		pos += hdrLen
	}
}
