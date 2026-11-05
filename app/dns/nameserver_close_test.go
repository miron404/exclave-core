package dns

import (
	"net/url"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
)

// An answer that arrives after its name server was closed, as happens when a
// test instance is torn down with a lookup still out, used to write into the
// cache Close had cleared, and panicked the whole process.
func TestAnswerAfterCloseIsDropped(t *testing.T) {
	u, err := url.Parse("tcp+local://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := NewTCPLocalNameServer(u)
	if err != nil {
		t.Fatal(err)
	}
	u, err = url.Parse("https+local://127.0.0.1/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	doh := NewDoHLocalNameServer(u)

	answer := func() *IPRecord {
		return &IPRecord{IP: []net.Address{net.ParseAddress("192.0.2.1")}, Expire: time.Now().Add(time.Minute), TTL: 60}
	}
	req := &dnsRequest{reqType: dns.TypeA, domain: "example.com.", start: time.Now()}

	_ = tcp.Close()
	tcp.updateIP(req, answer())
	_ = doh.Close()
	doh.updateIP(req, answer())

	udp := NewClassicNameServer(net.UDPDestination(net.ParseAddress("127.0.0.1"), 53), nil)
	_ = udp.Close()
	udp.updateIP("example.com.", record{A: answer()})
}
