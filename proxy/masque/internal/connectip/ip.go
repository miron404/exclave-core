/*
Copyright 2024 Marten Seemann

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// https://github.com/quic-go/connect-ip-go

package connectip

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	ipProtoICMP   = 1
	ipProtoICMPv6 = 58
)

func parseIPHeader(b []byte) (src, dst netip.Addr, ipProto uint8, err error) {
	if len(b) == 0 {
		return netip.Addr{}, netip.Addr{}, 0, errors.New("connect-ip: empty packet")
	}
	switch ipVersion(b) {
	case 4:
		if len(b) < ipv4.HeaderLen {
			return netip.Addr{}, netip.Addr{}, 0, errors.New("connect-ip: IPv4 packet too short")
		}
		if err := validateIPv4Checksum(b); err != nil {
			return netip.Addr{}, netip.Addr{}, 0, err
		}
		if err := validateIPv4TotalLength(b); err != nil {
			return netip.Addr{}, netip.Addr{}, 0, err
		}
	case 6:
		if len(b) < ipv6.HeaderLen {
			return netip.Addr{}, netip.Addr{}, 0, errors.New("connect-ip: IPv6 packet too short")
		}
		if err := validateIPv6PayloadLength(b); err != nil {
			return netip.Addr{}, netip.Addr{}, 0, err
		}
	}
	return parseTruncatedIPHeader(b)
}

func parseTruncatedIPHeader(b []byte) (src, dst netip.Addr, ipProto uint8, err error) {
	if len(b) == 0 {
		return netip.Addr{}, netip.Addr{}, 0, errors.New("connect-ip: empty packet")
	}
	switch v := ipVersion(b); v {
	default:
		return netip.Addr{}, netip.Addr{}, 0, fmt.Errorf("connect-ip: unknown IP versions: %d", v)
	case 4:
		if len(b) < ipv4.HeaderLen {
			return netip.Addr{}, netip.Addr{}, 0, errors.New("connect-ip: IPv4 packet too short")
		}
		src = netip.AddrFrom4([4]byte(b[12:16]))
		dst = netip.AddrFrom4([4]byte(b[16:20]))
		ipProto = b[9]
	case 6:
		if len(b) < ipv6.HeaderLen {
			return netip.Addr{}, netip.Addr{}, 0, errors.New("connect-ip: IPv6 packet too short")
		}
		src = netip.AddrFrom16([16]byte(b[8:24]))
		dst = netip.AddrFrom16([16]byte(b[24:40]))
		if ipProto, _, err = ipv6UpperLayerProtocol(b); err != nil {
			return netip.Addr{}, netip.Addr{}, 0, err
		}
	}
	return src, dst, ipProto, nil
}

func isAllowedSource(src netip.Addr, prefixes []netip.Prefix, routes []IPRoute) bool {
	if prefixes == nil {
		return true
	}
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(src) }) ||
		slices.ContainsFunc(routes, func(r IPRoute) bool { return r.contains(src) })
}

func isAllowedDestination(dst netip.Addr, ipProto uint8, prefixes []netip.Prefix, routes []IPRoute) bool {
	for _, p := range prefixes {
		if p.Contains(dst) {
			return true
		}
	}
	isICMP := (dst.Is4() && ipProto == ipProtoICMP) || (dst.Is6() && ipProto == ipProtoICMPv6)
	isFragment := dst.Is6() && ipProto == ipProtoFragment
	for _, r := range routes {
		if !r.contains(dst) {
			continue
		}
		if isICMP || isFragment || r.IPProtocol == 0 || r.IPProtocol == ipProto {
			return true
		}
	}
	return false
}

func ipVersion(b []byte) uint8 {
	return b[0] >> 4
}
