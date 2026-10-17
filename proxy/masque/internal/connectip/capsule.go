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
	"io"
	"net/netip"

	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

const (
	capsuleTypeDatagram           http3.CapsuleType = 0
	capsuleTypeAddressAssign      http3.CapsuleType = 1
	capsuleTypeAddressRequest     http3.CapsuleType = 2
	capsuleTypeRouteAdvertisement http3.CapsuleType = 3
)

const (
	maxAddressesPerCapsule = 8192
	maxRoutesPerCapsule    = 8192
)

type addressAssignCapsule struct {
	AssignedAddresses []AssignedAddress
}

type AssignedAddress struct {
	RequestID AddressRequestID
	IPPrefix  netip.Prefix
}

func (a AssignedAddress) Rejected() bool {
	return a.IPPrefix == rejectedIPv4Prefix || a.IPPrefix == rejectedIPv6Prefix
}

func (a AssignedAddress) len() int {
	return quicvarint.Len(uint64(a.RequestID)) + 1 + a.IPPrefix.Addr().BitLen()/8 + 1
}

type addressRequestCapsule struct {
	RequestIDs []AddressRequestID
	Prefixes   []netip.Prefix
}

func parseAddressAssignCapsule(r http3.CapsuleReader) (*addressAssignCapsule, error) {
	var assignedAddresses []AssignedAddress
	for r.Remaining() > 0 {
		if len(assignedAddresses) >= maxAddressesPerCapsule {
			return nil, fmt.Errorf("ADDRESS_ASSIGN capsule contains too many addresses (maximum %d)", maxAddressesPerCapsule)
		}
		requestID, prefix, err := parseAddress(r)
		if err != nil {
			return nil, err
		}
		assignedAddresses = append(assignedAddresses, AssignedAddress{RequestID: AddressRequestID(requestID), IPPrefix: prefix})
	}
	return &addressAssignCapsule{AssignedAddresses: assignedAddresses}, nil
}

func (c *addressAssignCapsule) append(b []byte) []byte {
	totalLen := 0
	for _, addr := range c.AssignedAddresses {
		totalLen += addr.len()
	}

	b = quicvarint.Append(b, uint64(capsuleTypeAddressAssign))
	b = quicvarint.Append(b, uint64(totalLen))

	for _, addr := range c.AssignedAddresses {
		b = quicvarint.Append(b, uint64(addr.RequestID))
		if addr.IPPrefix.Addr().Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, addr.IPPrefix.Addr().AsSlice()...)
		b = append(b, byte(addr.IPPrefix.Bits()))
	}
	return b
}

func parseAddressRequestCapsule(r http3.CapsuleReader) (*addressRequestCapsule, error) {
	if r.Remaining() == 0 {
		return nil, errors.New("ADDRESS_REQUEST capsule contains no addresses")
	}
	capsule := &addressRequestCapsule{}
	for r.Remaining() > 0 {
		if len(capsule.Prefixes) >= maxAddressesPerCapsule {
			return nil, fmt.Errorf("ADDRESS_REQUEST capsule contains too many addresses (maximum %d)", maxAddressesPerCapsule)
		}
		requestID, prefix, err := parseAddress(r)
		if err != nil {
			return nil, err
		}
		if requestID == 0 {
			return nil, errors.New("ADDRESS_REQUEST capsule contains a zero request ID")
		}
		capsule.RequestIDs = append(capsule.RequestIDs, AddressRequestID(requestID))
		capsule.Prefixes = append(capsule.Prefixes, prefix)
	}
	return capsule, nil
}

func (c *addressRequestCapsule) append(b []byte) []byte {
	var totalLen int
	for i, p := range c.Prefixes {
		totalLen += quicvarint.Len(uint64(c.RequestIDs[i])) + 1 + p.Addr().BitLen()/8 + 1
	}

	b = quicvarint.Append(b, uint64(capsuleTypeAddressRequest))
	b = quicvarint.Append(b, uint64(totalLen))

	for i, p := range c.Prefixes {
		b = quicvarint.Append(b, uint64(c.RequestIDs[i]))
		if p.Addr().Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, p.Addr().AsSlice()...)
		b = append(b, byte(p.Bits()))
	}
	return b
}

func parseAddress(r io.Reader) (requestID uint64, prefix netip.Prefix, _ error) {
	vr := quicvarint.NewReader(r)
	requestID, err := quicvarint.Read(vr)
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	ipVersion, err := vr.ReadByte()
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	var ip netip.Addr
	switch ipVersion {
	case 4:
		var ipv4 [4]byte
		if _, err := io.ReadFull(r, ipv4[:]); err != nil {
			return 0, netip.Prefix{}, err
		}
		ip = netip.AddrFrom4(ipv4)
	case 6:
		var ipv6 [16]byte
		if _, err := io.ReadFull(r, ipv6[:]); err != nil {
			return 0, netip.Prefix{}, err
		}
		ip = netip.AddrFrom16(ipv6)
	default:
		return 0, netip.Prefix{}, fmt.Errorf("invalid IP version: %d", ipVersion)
	}
	prefixLen, err := vr.ReadByte()
	if err != nil {
		return 0, netip.Prefix{}, err
	}
	if int(prefixLen) > ip.BitLen() {
		return 0, netip.Prefix{}, fmt.Errorf("prefix length %d exceeds IP address length (%d)", prefixLen, ip.BitLen())
	}
	prefix = netip.PrefixFrom(ip, int(prefixLen))
	if prefix != prefix.Masked() {
		return 0, netip.Prefix{}, errors.New("lower bits not covered by prefix length are not all zero")
	}
	return requestID, prefix, nil
}

type routeAdvertisementCapsule struct {
	IPAddressRanges []IPRoute
}

func (c *routeAdvertisementCapsule) append(b []byte) []byte {
	var totalLen int
	for _, ipRange := range c.IPAddressRanges {
		totalLen += ipRange.len()
	}

	b = quicvarint.Append(b, uint64(capsuleTypeRouteAdvertisement))
	b = quicvarint.Append(b, uint64(totalLen))

	for _, ipRange := range c.IPAddressRanges {
		if ipRange.StartIP.Is4() {
			b = append(b, 4)
		} else {
			b = append(b, 6)
		}
		b = append(b, ipRange.StartIP.AsSlice()...)
		b = append(b, ipRange.EndIP.AsSlice()...)
		b = append(b, ipRange.IPProtocol)
	}
	return b
}

type IPRoute struct {
	StartIP    netip.Addr
	EndIP      netip.Addr
	IPProtocol uint8
}

func (r IPRoute) len() int {
	return 1 + r.StartIP.BitLen()/8 + r.EndIP.BitLen()/8 + 1
}

func (r IPRoute) contains(addr netip.Addr) bool {
	return r.StartIP.Compare(addr) <= 0 && addr.Compare(r.EndIP) <= 0
}

func (r IPRoute) Prefixes() []netip.Prefix {
	return rangeToPrefixes(r.StartIP, r.EndIP)
}

func validateRouteAdvertisement(routes []IPRoute) error {
	var numIPv4, numIPv4Protocol0, numIPv6Protocol0 int
	for _, route := range routes {
		if !route.StartIP.IsValid() || !route.EndIP.IsValid() {
			return errors.New("invalid route: IP addresses must be valid")
		}
		if route.StartIP.Is4() != route.EndIP.Is4() {
			return errors.New("invalid route: IP addresses must have the same address family")
		}
		if route.StartIP.Zone() != "" || route.EndIP.Zone() != "" {
			return errors.New("invalid route: IP addresses must not have zones")
		}
		if route.StartIP.Compare(route.EndIP) > 0 {
			return fmt.Errorf("invalid route: start IP %s is greater than end IP %s", route.StartIP, route.EndIP)
		}
		if route.StartIP.Is4() {
			numIPv4++
			if route.IPProtocol == 0 {
				numIPv4Protocol0++
			}
		} else if route.IPProtocol == 0 {
			numIPv6Protocol0++
		}
	}

	for i := 1; i < len(routes); i++ {
		a := routes[i-1]
		b := routes[i]
		if a.StartIP.BitLen() > b.StartIP.BitLen() {
			return errors.New("route IP versions must be in increasing order")
		}
		if a.StartIP.BitLen() != b.StartIP.BitLen() {
			continue
		}
		if a.IPProtocol > b.IPProtocol {
			return errors.New("route IP protocols must be in increasing order")
		}
		if a.IPProtocol == b.IPProtocol && a.EndIP.Compare(b.StartIP) >= 0 {
			return errors.New("route address ranges must be disjoint and in increasing order")
		}
	}

	ipv4 := routes[:numIPv4]
	if err := validateNonOverlappingRoutes(ipv4[:numIPv4Protocol0], ipv4[numIPv4Protocol0:]); err != nil {
		return err
	}
	ipv6 := routes[numIPv4:]
	return validateNonOverlappingRoutes(ipv6[:numIPv6Protocol0], ipv6[numIPv6Protocol0:])
}

func validateNonOverlappingRoutes(all, specific []IPRoute) error {
	var j int
	for i, b := range specific {
		if i > 0 && specific[i-1].IPProtocol != b.IPProtocol {
			j = 0
		}
		for j < len(all) {
			a := all[j]
			if a.EndIP.Compare(b.StartIP) < 0 {
				j++
				continue
			}
			if b.EndIP.Compare(a.StartIP) < 0 {
				break
			}
			return errors.New("route overlaps a route for all IP protocols")
		}
	}
	return nil
}

func parseRouteAdvertisementCapsule(r http3.CapsuleReader) (*routeAdvertisementCapsule, error) {
	var ranges []IPRoute
	for r.Remaining() > 0 {
		if len(ranges) >= maxRoutesPerCapsule {
			return nil, fmt.Errorf("ROUTE_ADVERTISEMENT capsule contains too many routes (maximum %d)", maxRoutesPerCapsule)
		}
		ipRange, err := parseIPAddressRange(r)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, ipRange)
	}
	if err := validateRouteAdvertisement(ranges); err != nil {
		return nil, err
	}
	return &routeAdvertisementCapsule{IPAddressRanges: ranges}, nil
}

func parseIPAddressRange(r io.Reader) (IPRoute, error) {
	var ipVersion uint8
	if err := binary.Read(r, binary.LittleEndian, &ipVersion); err != nil {
		return IPRoute{}, err
	}

	var startIP, endIP netip.Addr
	switch ipVersion {
	case 4:
		var start, end [4]byte
		if _, err := io.ReadFull(r, start[:]); err != nil {
			return IPRoute{}, err
		}
		if _, err := io.ReadFull(r, end[:]); err != nil {
			return IPRoute{}, err
		}
		startIP = netip.AddrFrom4(start)
		endIP = netip.AddrFrom4(end)
	case 6:
		var start, end [16]byte
		if _, err := io.ReadFull(r, start[:]); err != nil {
			return IPRoute{}, err
		}
		if _, err := io.ReadFull(r, end[:]); err != nil {
			return IPRoute{}, err
		}
		startIP = netip.AddrFrom16(start)
		endIP = netip.AddrFrom16(end)
	default:
		return IPRoute{}, fmt.Errorf("invalid IP version: %d", ipVersion)
	}

	var ipProtocol uint8
	if err := binary.Read(r, binary.LittleEndian, &ipProtocol); err != nil {
		return IPRoute{}, err
	}
	return IPRoute{
		StartIP:    startIP,
		EndIP:      endIP,
		IPProtocol: ipProtocol,
	}, nil
}
