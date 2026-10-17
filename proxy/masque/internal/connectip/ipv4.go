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

	"golang.org/x/net/ipv4"
)

func calculateIPv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func validateIPv4Checksum(b []byte) error {
	hdrLen := int(b[0]&0x0f) * 4
	if hdrLen < ipv4.HeaderLen || hdrLen > len(b) {
		return fmt.Errorf("connect-ip: invalid IPv4 header length: %d", hdrLen)
	}
	var sum uint32
	for i := 0; i < hdrLen; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if sum != 0xffff {
		return errors.New("connect-ip: invalid IPv4 header checksum")
	}
	return nil
}

func validateIPv4TotalLength(b []byte) error {
	if l := int(binary.BigEndian.Uint16(b[2:4])); l != len(b) {
		return fmt.Errorf("connect-ip: IPv4 total length (%d) doesn't match packet size (%d)", l, len(b))
	}
	return nil
}
