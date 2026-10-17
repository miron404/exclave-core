/*
Copyright 2024 Marten Seemann

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

// https://github.com/quic-go/connect-ip-go

package connectip

import (
	"net/netip"
)

func rangeToPrefixes(start, end netip.Addr) []netip.Prefix {
	var prefixes []netip.Prefix
	for current := start; current.Compare(end) <= 0; {
		prefix := findLargestPrefix(current, end)
		prefixes = append(prefixes, prefix)

		lastIP := lastIPInPrefix(prefix)
		if lastIP.Compare(end) >= 0 {
			break
		}
		current = lastIP.Next()
	}
	return prefixes
}

func findLargestPrefix(start, end netip.Addr) netip.Prefix {
	if start == end {
		return netip.PrefixFrom(start, start.BitLen())
	}

	var prefixLen int
	for prefixLen = start.BitLen(); prefixLen > 0; prefixLen-- {
		prefix := netip.PrefixFrom(start, prefixLen-1)
		if lastIPInPrefix(prefix).Compare(end) > 0 || !isAligned(start, prefixLen-1) {
			break
		}
	}
	return netip.PrefixFrom(start, prefixLen)
}

func lastIPInPrefix(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr()
	bits := addr.As16()

	hostBits := addr.BitLen() - prefix.Bits()

	for i := len(bits) - 1; i >= 0 && hostBits > 0; i-- {
		bitsInThisByte := min(8, hostBits)
		mask := byte((1 << bitsInThisByte) - 1)
		bits[i] |= mask
		hostBits -= bitsInThisByte
	}

	if addr.Is4() {
		return netip.AddrFrom4([4]byte(bits[12:16]))
	}
	return netip.AddrFrom16(bits)
}

func isAligned(addr netip.Addr, prefixLen int) bool {
	bits := addr.As16()

	hostBits := addr.BitLen() - prefixLen
	for i := len(bits) - 1; i >= 0 && hostBits > 0; i-- {
		bitsInThisByte := min(8, hostBits)
		mask := byte((1 << bitsInThisByte) - 1)
		if bits[i]&mask != 0 {
			return false
		}
		hostBits -= bitsInThisByte
	}
	return true
}
