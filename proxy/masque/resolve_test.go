package masque

import (
	"net/netip"
	"testing"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/features/dns"
)

// dualStackDNS answers every name with an IPv6 address first, the order that
// used to hand a tunnel without IPv6 an address it could not dial.
type dualStackDNS struct{}

var (
	testIPv4 = net.ParseIP("192.0.2.1")
	testIPv6 = net.ParseIP("2001:db8::1")
)

func (dualStackDNS) Type() interface{} { return dns.ClientType() }
func (dualStackDNS) Start() error      { return nil }
func (dualStackDNS) Close() error      { return nil }

func (dualStackDNS) LookupIP(string) ([]net.IP, error) {
	return []net.IP{testIPv6, testIPv4}, nil
}

func (dualStackDNS) LookupIPv4(string) ([]net.IP, error) {
	return []net.IP{testIPv4}, nil
}

func (dualStackDNS) LookupIPv6(string) ([]net.IP, error) {
	return []net.IP{testIPv6}, nil
}

// A tunnel resized below the IPv6 minimum leaves its IPv6 address off even
// though the device was assigned one, so a name must resolve to IPv4 only.
func TestResolveFollowsTheFamiliesTheTunnelCarries(t *testing.T) {
	outbound := &Outbound{
		dns: dualStackDNS{},
		localAddresses: []netip.Addr{
			netip.MustParseAddr("172.16.0.2"),
			netip.MustParseAddr("2606:4700:110::2"),
		},
	}
	destination := net.TCPDestination(net.DomainAddress("example.com"), 443)

	shrunk := &tunnel{outbound: outbound, hasIPv4: true}
	resolved, err := shrunk.resolve(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.Address.IP().Equal(testIPv4) {
		t.Fatalf("resolved to %v on a tunnel without IPv6", resolved.Address)
	}
	if shrunk.carries(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("a tunnel without IPv6 claims to carry an IPv6 destination")
	}

	full := &tunnel{outbound: outbound, hasIPv4: true, hasIPv6: true}
	resolved, err = full.resolve(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !resolved.Address.IP().Equal(testIPv6) {
		t.Fatalf("resolved to %v, want the first answer on a dual stack tunnel", resolved.Address)
	}
}
