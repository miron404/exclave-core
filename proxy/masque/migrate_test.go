package masque

import (
	"context"
	"crypto/tls"
	"io"
	gonet "net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

// socketDialer hands out a fresh loopback socket for every dial, the way the
// core dialer does once the device is on another network.
type socketDialer struct{}

func (socketDialer) Dial(_ context.Context, destination net.Destination) (internet.Connection, error) {
	socket, err := gonet.ListenUDP("udp", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	return &internet.PacketConnWrapper{Conn: socket, Dest: &gonet.UDPAddr{
		IP:   destination.Address.IP(),
		Port: int(destination.Port),
	}}, nil
}

func (socketDialer) Address() net.Address { return nil }

// echoServer accepts QUIC connections and echoes every stream back.
func echoServer(t *testing.T) *gonet.UDPAddr {
	t.Helper()
	serverTLS, _ := testTLS(t)
	serverTLS.NextProtos = []string{http3.NextProtoH3}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				for {
					stream, err := conn.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() {
						_, _ = io.Copy(stream, stream)
						_ = stream.Close()
					}()
				}
			}()
		}
	}()
	return listener.Addr().(*gonet.UDPAddr)
}

func echo(t *testing.T, conn *quic.Conn, message string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := stream.Write([]byte(message)); err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	answer, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(answer) != message {
		t.Fatalf("echoed %q, want %q", answer, message)
	}
}

// A network change moves the connection onto a new socket rather than
// replacing it, so the CONNECT-IP session and the flows in the tunnel survive.
// The connection has to keep working after the move, run on the new socket,
// and do so more than once.
func TestMigrationKeepsTheConnection(t *testing.T) {
	endpoint := echoServer(t)
	outbound := &Outbound{
		serverAddress: net.IPAddress(endpoint.IP),
		serverPort:    net.Port(endpoint.Port),
	}
	dialer := socketDialer{}

	socket, _, isSocket, err := listenPacket(context.Background(), dialer, outbound.endpoint(net.Network_UDP), endpoint)
	if err != nil || !isSocket {
		t.Fatal("no socket:", err)
	}
	transport := &quic.Transport{Conn: socket, ConnectionIDLength: 20}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := transport.Dial(ctx, endpoint, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	sess := &ipSession{
		canDiscoverPathMTU: true,
		quicConn:           conn,
		quicTransport:      transport,
		packetConn:         socket,
	}
	defer sess.Close()

	echo(t, conn, "before")
	for round := 1; round <= 2; round++ {
		if err := outbound.migrate(ctx, dialer, sess); err != nil {
			t.Fatalf("move %d: %v", round, err)
		}
		// quic-go switches on its next send, so traffic comes first.
		echo(t, conn, "after a move")
		moved := sess.migrations[len(sess.migrations)-1].packetConn.LocalAddr()
		if conn.LocalAddr().String() != moved.String() {
			t.Fatalf("move %d: the connection runs on %v, not the new socket %v", round, conn.LocalAddr(), moved)
		}
	}
}

// The sockets a session collects are bounded; past the bound a network change
// redials instead, which releases them all.
func TestMigrationIsBounded(t *testing.T) {
	sess := &ipSession{
		canDiscoverPathMTU: true,
		quicConn:           new(quic.Conn),
		migrations:         make([]migratedPath, maxMigrations),
	}
	if err := (&Outbound{}).migrate(context.Background(), socketDialer{}, sess); err == nil {
		t.Fatal("a session past the bound was moved again")
	}
	if err := (&Outbound{}).migrate(context.Background(), socketDialer{}, &ipSession{}); err == nil {
		t.Fatal("an HTTP/2 session was moved")
	}
}

// A network change reaching an idle tunnel must not dial anything by itself:
// it is held for the next dial, which is made on the new network anyway.
func TestNetworkChangeIsHeldNotActedOn(t *testing.T) {
	tun := &tunnel{networkChanged: make(chan struct{}, 1)}
	tun.NetworkChanged()
	tun.NetworkChanged() // coalesced, never blocks
	changed, err := tun.sleepUnlessNetworkChanges(context.Background(), time.Hour)
	if err != nil || !changed {
		t.Fatal("a pending network change did not cut the backoff short")
	}
	tun.NetworkChanged()
	tun.takeNetworkChange()
	select {
	case <-tun.networkChanged:
		t.Fatal("a change answered by a dial was left pending")
	default:
	}
}
