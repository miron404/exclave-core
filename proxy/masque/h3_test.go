package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	gonet "net"
	"net/http"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

// nonSyscallPacketConn mimics singbridge's statCounterPacketConn: a net.PacketConn
// that deliberately does not expose syscall.Conn, so quic-go cannot use OOB.
type nonSyscallPacketConn struct{ gonet.PacketConn }

type testCounter struct{ value atomic.Int64 }

func (c *testCounter) Value() int64      { return c.value.Load() }
func (c *testCounter) Set(v int64) int64 { return c.value.Swap(v) }
func (c *testCounter) Add(v int64) int64 { return c.value.Add(v) }

func testTLS(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []gonet.IP{gonet.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}},
		NextProtos:   []string{http3.NextProtoH3},
	}, pool
}

// The tunnel dials QUIC itself and hands the connection to http3, rather than
// letting http3.Transport dial. This pins that the peer's SETTINGS still reach
// the client that way, including over a packet conn that hides syscall.Conn,
// which is what the core dialer returns.
func TestSettingsArriveOverSelfDialedTransport(t *testing.T) {
	serverTLS, pool := testTLS(t)

	serverConn, err := gonet.ListenUDP("udp", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	server := &http3.Server{
		TLSConfig:       serverTLS,
		EnableDatagrams: true,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		Handler:         http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}
	go func() { _ = server.Serve(serverConn) }()
	defer server.Close()

	clientConn, err := gonet.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	// Exactly the construction proxy/masque uses.
	transport := &quic.Transport{Conn: &nonSyscallPacketConn{clientConn}, ConnectionIDLength: 20}
	defer transport.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	quicConn, err := transport.Dial(ctx, serverConn.LocalAddr(), &tls.Config{
		ServerName: "localhost",
		RootCAs:    pool,
		NextProtos: []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true, KeepAlivePeriod: 30 * time.Second})
	if err != nil {
		t.Fatal("QUIC handshake failed:", err)
	}
	t.Log("QUIC handshake completed")

	h3 := &http3.Transport{
		EnableDatagrams:    true,
		AdditionalSettings: map[uint64]uint64{0x276: 1},
		DisableCompression: true,
	}
	defer h3.Close()
	clientCC := h3.NewClientConn(quicConn)

	select {
	case <-clientCC.ReceivedSettings():
		t.Log("SETTINGS received; datagrams =", clientCC.Settings().EnableDatagrams)
	case <-time.After(5 * time.Second):
		t.Fatal("SETTINGS never arrived")
	}
}

func TestNextHopMTU(t *testing.T) {
	ipv4 := make([]byte, 28)
	ipv4[0] = 4 << 4
	ipv4[20] = 3 // destination unreachable
	ipv4[21] = 4 // fragmentation needed
	ipv4[26], ipv4[27] = 0x04, 0xd2
	if got := nextHopMTU(ipv4); got != 1234 {
		t.Errorf("IPv4: got %d, want 1234", got)
	}

	ipv6 := make([]byte, 48)
	ipv6[0] = 6 << 4
	ipv6[40] = 2 // packet too big
	ipv6[47] = 0xd2
	ipv6[46] = 0x04
	if got := nextHopMTU(ipv6); got != 1234 {
		t.Errorf("IPv6: got %d, want 1234", got)
	}

	for name, packet := range map[string][]byte{
		"empty":           nil,
		"short":           make([]byte, 8),
		"other ICMP type": append([]byte{4 << 4}, make([]byte, 27)...),
	} {
		if got := nextHopMTU(packet); got != 0 {
			t.Errorf("%s: got %d, want 0", name, got)
		}
	}
}

// The socket must reach quic-go with its own methods intact: quic-go decides
// whether it can discover the path MTU from them, and its out of band setup
// hands the packet conn to golang.org/x/net/ipv4, which asserts it to net.Conn.
// A wrapper missing any of that panics deep inside the dial rather than failing
// to compile, so what unwrapping returns is checked against both, and put
// through a real dial.
func TestUnwrappedSocketIsUsableByQUIC(t *testing.T) {
	socket, err := gonet.ListenUDP("udp", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()

	read, write := &testCounter{}, &testCounter{}
	dialed := &internet.StatCouterConnection{
		Connection:   &internet.PacketConnWrapper{Conn: socket, Dest: socket.LocalAddr()},
		ReadCounter:  read,
		WriteCounter: write,
	}

	packetConn, counters, ok := unwrapPacketConn(dialed)
	if !ok {
		t.Fatal("the socket was not recognized")
	}
	if packetConn != gonet.PacketConn(socket) {
		t.Error("unwrapping did not reach the socket")
	}
	if counters.read != read || counters.write != write {
		t.Error("the counters were not carried out")
	}
	if _, ok := packetConn.(gonet.Conn); !ok {
		t.Error("not a net.Conn: golang.org/x/net/ipv4 will panic on it")
	}
	if _, ok := packetConn.(syscall.Conn); !ok {
		t.Error("not a syscall.Conn: quic-go will not discover the path MTU")
	}

	serverTLS, pool := testTLS(t)
	serverConn, err := gonet.ListenUDP("udp", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	server := &http3.Server{
		TLSConfig:       serverTLS,
		EnableDatagrams: true,
		QUICConfig:      &quic.Config{EnableDatagrams: true},
		Handler:         http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}
	go func() { _ = server.Serve(serverConn) }()
	defer server.Close()

	transport := &quic.Transport{Conn: packetConn, ConnectionIDLength: 20}
	defer transport.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := transport.Dial(ctx, serverConn.LocalAddr(), &tls.Config{
		ServerName: "localhost",
		RootCAs:    pool,
		NextProtos: []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true, KeepAlivePeriod: 30 * time.Second})
	if err != nil {
		t.Fatal("QUIC handshake failed:", err)
	}
	defer conn.CloseWithError(0, "")
}
