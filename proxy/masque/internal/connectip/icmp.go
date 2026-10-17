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

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func icmpInvokingPacket(b []byte, ipProto uint8) (invoking []byte, ok bool) {
	var msg []byte
	switch {
	case ipVersion(b) == 4 && ipProto == ipProtoICMP:
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return nil, false
		}
		msg = b[int(b[0]&0x0f)*4:]
		if len(msg) == 0 {
			return nil, false
		}
		switch ipv4.ICMPType(msg[0]) {
		case ipv4.ICMPTypeDestinationUnreachable, ipv4.ICMPTypeTimeExceeded, ipv4.ICMPTypeParameterProblem:
		default:
			return nil, false
		}
	case ipVersion(b) == 6 && ipProto == ipProtoICMPv6:
		_, msg, _ = ipv6UpperLayerProtocol(b)
		if len(msg) == 0 || msg[0] >= 128 {
			return nil, false
		}
	default:
		return nil, false
	}
	if len(msg) < 8 {
		return nil, true
	}
	return msg[8:], true
}

func composeICMPTooLargePacket(b []byte, mtu int) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("connect-ip: empty packet")
	}

	var icmpMessage *icmp.Message
	var psh []byte
	switch v := ipVersion(b); v {
	case 4:
		if len(b) < ipv4.HeaderLen {
			return nil, errors.New("connect-ip: IPv4 packet too short")
		}
		const maxDataLen = 576 - ipv4.HeaderLen - 8
		icmpMessage = &icmp.Message{
			Type: ipv4.ICMPTypeDestinationUnreachable,
			Code: 4,
			Body: &icmp.PacketTooBig{
				MTU:  mtu,
				Data: b[:min(len(b), maxDataLen)],
			},
		}
	case 6:
		if len(b) < ipv6.HeaderLen {
			return nil, errors.New("connect-ip: IPv6 packet too short")
		}
		icmpMessage = &icmp.Message{
			Type: ipv6.ICMPTypePacketTooBig,
			Body: &icmp.PacketTooBig{
				MTU:  mtu,
				Data: b[:min(len(b), 1232)],
			},
		}
		psh = icmp.IPv6PseudoHeader(b[24:40], b[8:24])
	default:
		return nil, fmt.Errorf("connect-ip: unknown IP version: %d", v)
	}

	icmp, err := icmpMessage.Marshal(psh)
	if err != nil {
		return nil, fmt.Errorf("connect-ip: failed to marshal ICMP message: %w", err)
	}

	if ipVersion(b) == 4 {
		var header [ipv4.HeaderLen]byte
		header[0] = 4<<4 | ipv4.HeaderLen>>2
		ipLen := ipv4.HeaderLen + len(icmp)
		binary.BigEndian.PutUint16(header[2:4], uint16(ipLen))
		header[8] = 64
		header[9] = 1
		copy(header[12:16], b[16:20])
		copy(header[16:20], b[12:16])
		binary.BigEndian.PutUint16(header[10:12], calculateIPv4Checksum(header[:]))
		return append(header[:], icmp...), nil
	}

	var header [ipv6.HeaderLen]byte
	header[0] = 6 << 4
	binary.BigEndian.PutUint16(header[4:6], uint16(len(icmp)))
	header[6] = 58
	header[7] = 64
	copy(header[8:24], b[24:40])
	copy(header[24:40], b[8:24])
	return append(header[:], icmp...), nil
}
