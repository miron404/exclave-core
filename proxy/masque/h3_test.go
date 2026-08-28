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
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// nonSyscallPacketConn mimics singbridge's statCounterPacketConn: a net.PacketConn
// that deliberately does not expose syscall.Conn, so quic-go cannot use OOB.
type nonSyscallPacketConn struct{ gonet.PacketConn }

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
