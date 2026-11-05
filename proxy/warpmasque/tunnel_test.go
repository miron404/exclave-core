package warpmasque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/proxy/wireguard/netstack"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

var tunnelTestAddress = netip.MustParseAddr("172.16.0.2")

// openTCP starts a TCP connection inside the tunnel, whose SYN is the packet
// the stack sends, and returns what stops it.
func openTCP(t *testing.T, tun *tunnel) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _, _ = tun.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("192.0.2.1:443")) }()
	return cancel
}

// When a session ends, its outgoing pump has to let go at once, and the next
// packet the stack sends has to reach the supervisor, which dials the next
// session for it. A pump parked in a device read used to keep it for a couple
// of seconds and then take that packet and drop it, so every reconnect, which
// against Cloudflare is every change of network, lost its first packet.
func TestFirstPacketAfterSessionLossReachesTheSupervisor(t *testing.T) {
	device, netStack, _, err := netstack.CreateNetTUN([]netip.Addr{tunnelTestAddress}, 1280, false)
	if err != nil {
		t.Fatal(err)
	}
	tun := &tunnel{device: device, net: netStack, mtu: 1280, hasIPv4: true,
		packets: make(chan outgoingPacket), carried: make(chan outgoingPacket, 1)}
	tun.bufferPool.New = func() any { b := make([]byte, 1280+datagramContextIDHeadroom); return &b }
	runCtx, stop := context.WithCancel(context.Background())
	defer func() {
		stop()
		_ = device.Close()
	}()
	go tun.readDevice(runCtx)

	pumpCtx, cancelPump := context.WithCancel(context.Background())
	pumpDone := make(chan error, 1)
	go func() { pumpDone <- tun.pumpToTunnel(pumpCtx, nil, make(chan []byte, 1)) }()
	time.Sleep(50 * time.Millisecond)

	cancelPump() // the session is lost
	select {
	case <-pumpDone:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("the pump did not stop when its session ended")
	}

	stopTCP := openTCP(t, tun)
	defer stopTCP()
	got := make(chan outgoingPacket, 1)
	go func() {
		var p outgoingPacket
		if _, open := tun.waitForPacket(runCtx, &p); open {
			got <- p
		}
	}()
	select {
	case p := <-got:
		if p.n == 0 {
			t.Fatal("the supervisor got an empty packet")
		}
	case <-time.After(time.Second):
		t.Fatal("the first packet after the session ended never reached the supervisor")
	}
}

// A packet a pump took just as its session ended is kept for the next one.
func TestCarriedPacketIsKeptForTheNextSession(t *testing.T) {
	tun := &tunnel{carried: make(chan outgoingPacket, 1)}
	tun.bufferPool.New = func() any { b := make([]byte, 8); return &b }
	first := outgoingPacket{buf: tun.bufferPool.Get().(*[]byte), n: 1}
	second := outgoingPacket{buf: tun.bufferPool.Get().(*[]byte), n: 2}
	tun.carry(first)
	tun.carry(second) // replaces the first, never blocks
	p, ok := tun.takeCarried()
	if !ok || p.n != 2 {
		t.Fatalf("carried %+v, %v; want the newest packet", p, ok)
	}
	if _, ok := tun.takeCarried(); ok {
		t.Fatal("a carried packet was handed out twice")
	}
}

// countingDialer fails every dial at once, as on a network that refuses the
// endpoint, and counts them.
type countingDialer struct{ dials atomic.Int32 }

func (d *countingDialer) Dial(context.Context, net.Destination) (internet.Connection, error) {
	d.dials.Add(1)
	return nil, errors.New("unreachable")
}

func (*countingDialer) Address() net.Address { return nil }

// A tunnel that cannot reach its endpoint must not keep dialing on a timer for
// as long as it exists: it tries when something wants to send, and once that
// has stopped, it stops too. The old supervisor redialed every backoff period,
// up to every 30 seconds, forever, waking the radio of an idle phone on any
// network that blocks the endpoint.
func TestFailedDialWaitsForDemand(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	o := &Outbound{
		serverAddress:   net.ParseAddress("192.0.2.10"),
		serverPort:      443,
		serverName:      DefaultServerName,
		mtu:             1280,
		configuredMTU:   1280,
		keepalivePeriod: defaultKeepalivePeriod,
		privateKey:      key,
		localAddresses:  []netip.Addr{tunnelTestAddress},
	}
	dialer := new(countingDialer)
	tun, err := newTunnel(context.Background(), o, dialer)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	time.Sleep(300 * time.Millisecond)
	if n := dialer.dials.Load(); n != 0 {
		t.Fatalf("dialed %d times with nothing to send", n)
	}

	stopTCP := openTCP(t, tun)
	deadline := time.Now().Add(time.Second)
	for dialer.dials.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if dialer.dials.Load() == 0 {
		t.Fatal("a packet to send did not dial the tunnel")
	}
	// The connection gives up, and nothing else wants out.
	stopTCP()

	time.Sleep(3500 * time.Millisecond)
	if n := dialer.dials.Load(); n != 1 {
		t.Fatalf("dialed %d times; once nothing wants to send, a failed tunnel must stay quiet", n)
	}
}
