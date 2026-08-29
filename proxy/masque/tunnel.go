package masque

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"

	connectip "github.com/miron404/connect-ip-go"
	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/proxy/wireguard/netstack"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

const (
	// CONNECT-IP context ID 0 is encoded as a single byte QUIC varint.
	// Reserving that byte in front of every packet lets connect-ip-go build
	// outgoing datagrams without copying.
	datagramContextIDHeadroom = 1

	// pumpShutdownGrace bounds how long a reconnect waits for the previous
	// pumps to exit. A device reader may still be parked in a blocking read;
	// readMutex serializes it against the next cycle.
	pumpShutdownGrace = 2 * time.Second

	// minimumTunnelMTU is the floor for automatic MTU reduction: below the
	// IPv4 minimum reassembly buffer the tunnel is not worth keeping.
	minimumTunnelMTU = 576

	// minimumIPv6MTU is the smallest link an IPv6 stack will operate on; below
	// it the netstack refuses to send IPv6 at all.
	minimumIPv6MTU = 1280

	// pathMTUSettle is how long the limit has to stop improving before the
	// search is taken as finished. A refusal on its own means nothing: path MTU
	// discovery starts below what the tunnel sends and climbs, so early ones are
	// expected. What settles it is the limit no longer moving.
	pathMTUSettle = 5 * time.Second

	// icmpQueueSize bounds the ICMP answers waiting to go back into the stack.
	// They are advisory, so dropping one under pressure costs a retransmit.
	icmpQueueSize = 16

	reconnectDelayMin = 1 * time.Second
	reconnectDelayMax = 30 * time.Second

	// dialTimeout bounds a full tunnel setup. The CONNECT-IP handshake waits for
	// the peer's HTTP/3 SETTINGS without a deadline of its own, and keepalives
	// stop the QUIC connection from ever timing out, so a silent endpoint would
	// otherwise stall the tunnel forever instead of failing and being retried.
	dialTimeout = 20 * time.Second
)

// tunnel owns the userspace network stack that proxied connections are dialed
// on, plus the goroutine keeping a CONNECT-IP session attached to it.
//
// The session is re-established on failure. While no session is up the stack
// stays alive, so in-flight connections survive short outages instead of being
// reset.
type tunnel struct {
	outbound *Outbound
	device   wgtun.Device
	net      *netstack.Net
	mtu      int
	cancel   context.CancelFunc
	done     chan struct{}

	// readMutex serializes device reads across reconnect cycles. It also covers
	// the scratch the device read needs, which is reused rather than allocated
	// for every packet.
	readMutex   sync.Mutex
	readBuffers [][]byte
	readSizes   []int

	// Each of these reports once, so a condition that repeats per packet does
	// not fill the log.
	dropReported      sync.Once
	oversizedReported sync.Once

	// Progress of the path MTU search. Only the reading pump touches these.
	bestDatagramMTU int
	refusedSince    time.Time
}

func newTunnel(ctx context.Context, o *Outbound, dialer internet.Dialer) (*tunnel, error) {
	addresses := o.localAddresses
	if o.mtu < minimumIPv6MTU {
		// The stack rejects a link this small for IPv6, and would then fail to
		// come up at all, so those addresses are left off.
		addresses = make([]netip.Addr, 0, len(o.localAddresses))
		for _, address := range o.localAddresses {
			if address.Is4() {
				addresses = append(addresses, address)
			}
		}
		if len(addresses) == 0 {
			return nil, newError("the path only allows an MTU of ", o.mtu,
				", which cannot carry the IPv6 only addresses assigned to this device")
		}
	}
	device, netStack, _, err := netstack.CreateNetTUN(addresses, o.mtu, false)
	if err != nil {
		return nil, newError("failed to create virtual network stack").Base(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	t := &tunnel{
		outbound:    o,
		device:      device,
		net:         netStack,
		mtu:         o.mtu,
		cancel:      cancel,
		done:        make(chan struct{}),
		readBuffers: make([][]byte, 1),
		readSizes:   make([]int, 1),
	}
	go func() {
		defer close(t.done)
		t.maintain(runCtx, o, dialer)
	}()
	return t, nil
}

func (t *tunnel) Close() error {
	t.cancel()
	err := t.device.Close()
	<-t.done
	return err
}

func (t *tunnel) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return t.net.DialContextTCPAddrPort(ctx, addr)
}

func (t *tunnel) DialUDPAddrPort(laddr, raddr netip.AddrPort) (net.Conn, error) {
	return t.net.DialUDPAddrPort(laddr, raddr)
}

// readPacket reads one packet from the stack into a buffer that already has
// room for the datagram context ID. It returns the full buffer and the packet
// length.
func (t *tunnel) readPacket(buf []byte) (int, error) {
	t.readMutex.Lock()
	t.readBuffers[0] = buf[datagramContextIDHeadroom:]
	t.readSizes[0] = 0
	_, err := t.device.Read(t.readBuffers, t.readSizes, 0)
	n := t.readSizes[0]
	t.readBuffers[0] = nil
	t.readMutex.Unlock()
	if err != nil {
		return 0, err
	}
	return n, nil
}

// writePacket hands a packet to the stack. The caller owns the scratch, since
// the two writers run at the same time; reusing it keeps the hot path free of
// an allocation per packet.
func (t *tunnel) writePacket(scratch [][]byte, packet []byte) error {
	scratch[0] = packet
	_, err := t.device.Write(scratch, 0)
	scratch[0] = nil
	return err
}

// maintain keeps a CONNECT-IP session attached to the stack, reconnecting on
// failure with a capped exponential backoff.
//
// After the first session is lost the supervisor parks on a device read until
// something inside the stack actually wants to send. That keeps a tunnel that
// broke while idle from redialing in a loop, and the packet that woke it up is
// carried over into the new session instead of being dropped.
func (t *tunnel) maintain(ctx context.Context, o *Outbound, dialer internet.Dialer) {
	bufferPool := sync.Pool{New: func() any {
		buf := make([]byte, t.mtu+datagramContextIDHeadroom)
		return &buf
	}}
	backoff := reconnectDelayMin
	connected := false
	var pending []byte
	var pendingLength int

	for {
		if ctx.Err() != nil {
			return
		}

		if connected && pending == nil {
			buf := make([]byte, t.mtu+datagramContextIDHeadroom)
			n, err := t.readPacket(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				newError("failed to read from the virtual network stack").Base(err).AtWarning().WriteToLog()
				if sleep(ctx, backoff) != nil {
					return
				}
				continue
			}
			pending, pendingLength = buf, n
		}

		// The HTTP/2 transport keeps its request open for as long as the tunnel
		// lives, so the dial context cannot simply be cancelled once the dial
		// returns; it is handed to the session and released with it. Until then
		// a timer bounds how long the setup may take.
		dialCtx, cancelDial := context.WithCancel(ctx)
		dialTimer := time.AfterFunc(dialTimeout, cancelDial)
		sess, err := o.dial(dialCtx, dialer)
		timedOut := !dialTimer.Stop()
		if err != nil {
			cancelDial()
			if ctx.Err() != nil {
				return
			}
			if timedOut {
				err = newError("timed out after ", dialTimeout).Base(err)
			}
			newError("failed to establish the MASQUE tunnel").Base(err).AtWarning().WriteToLog()
			if sleep(ctx, backoff) != nil {
				return
			}
			backoff = min(backoff*2, reconnectDelayMax)
			continue
		}
		sess.cancel = cancelDial
		backoff = reconnectDelayMin
		connected = true
		newError("MASQUE tunnel established").AtInfo().WriteToLog()

		if pending != nil {
			if _, err := sess.ipConn.WritePacketBuffer(pending, datagramContextIDHeadroom, pendingLength); err != nil {
				newError("failed to send the first packet").Base(err).AtDebug().WriteToLog()
			}
			pending, pendingLength = nil, 0
		}

		errChan := make(chan error, 2)
		pumpCtx, cancelPumps := context.WithCancel(ctx)
		var wg sync.WaitGroup
		wg.Add(2)
		// A new connection starts its own search.
		t.bestDatagramMTU, t.refusedSince = 0, time.Time{}
		// The reader must never write to the device: the stack hands packets
		// out over an unbuffered channel that only the reader drains, so a
		// write that makes the stack answer would wait on the reader itself.
		icmpQueue := make(chan []byte, icmpQueueSize)
		wg.Add(1)
		go func() {
			defer wg.Done()
			scratch := make([][]byte, 1)
			for packet := range icmpQueue {
				if err := t.writePacket(scratch, packet); err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			defer close(icmpQueue)
			errChan <- t.pumpToTunnel(pumpCtx, sess, &bufferPool, icmpQueue)
		}()
		go func() {
			defer wg.Done()
			errChan <- t.pumpFromTunnel(sess, o.useHTTP2)
		}()

		err = <-errChan
		if ctx.Err() != nil {
			cancelPumps()
			sess.Close()
			return
		}
		newError("MASQUE tunnel lost, reconnecting").Base(err).AtInfo().WriteToLog()

		cancelPumps()
		sess.Close()
		waitPumps(&wg)
	}
}

// pumpToTunnel forwards packets from the stack into the CONNECT-IP session and
// injects any ICMP error the session generates back into the stack.
func (t *tunnel) pumpToTunnel(ctx context.Context, sess *ipSession, bufferPool *sync.Pool, icmpQueue chan<- []byte) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		bufPtr := bufferPool.Get().(*[]byte)
		n, err := t.readPacket(*bufPtr)
		if err != nil {
			bufferPool.Put(bufPtr)
			return err
		}
		if ctx.Err() != nil {
			bufferPool.Put(bufPtr)
			return ctx.Err()
		}
		icmp, err := sess.ipConn.WritePacketBuffer(*bufPtr, datagramContextIDHeadroom, n)
		bufferPool.Put(bufPtr)
		if err == nil && len(icmp) == 0 {
			// An ICMP answer means the packet was refused, not sent.
			sess.counters.addWrite(n)
		}
		if err != nil {
			if errors.As(err, new(*connectip.CloseError)) {
				return err
			}
			// A single rejected packet must not take the tunnel down, but it is
			// worth saying why once: a packet that never fits is an MTU that is
			// too high for the path, and it stalls everything except the
			// smallest exchanges.
			t.reportDroppedPacket(n, err)
			continue
		}
		if len(icmp) > 0 {
			// The packet did not fit a datagram on this path. The answer is an
			// ICMP "packet too big" naming the size that does fit, which makes
			// the stack shrink that one flow. That only helps flows that honour
			// it, so the size is also remembered for the tunnel as a whole.
			t.noteOversizedPacket(n, nextHopMTU(icmp), sess.canDiscoverPathMTU)
			select {
			case icmpQueue <- icmp:
			default:
				// The stack is already being told; one more answer adds nothing.
			}
		}
	}
}

// pumpFromTunnel forwards packets from the CONNECT-IP session into the stack.
func (t *tunnel) pumpFromTunnel(sess *ipSession, useHTTP2 bool) error {
	scratch := make([][]byte, 1)
	for {
		packet, err := sess.ipConn.ReadPacketZeroCopy(true)
		if err != nil {
			// Over QUIC a malformed datagram is recoverable, the stream is
			// what carries fatal errors. HTTP/2 has no datagrams, so every
			// read error there is fatal.
			if useHTTP2 || errors.As(err, new(*connectip.CloseError)) {
				return err
			}
			newError("failed to read from the tunnel").Base(err).AtDebug().WriteToLog()
			continue
		}
		sess.counters.addRead(len(packet))
		if err := t.writePacket(scratch, packet); err != nil {
			return err
		}
	}
}

// reportDroppedPacket explains the first packet the tunnel refused to carry.
func (t *tunnel) reportDroppedPacket(size int, err error) {
	t.dropReported.Do(func() {
		newError("dropping a packet of ", size, " bytes").Base(err).AtWarning().WriteToLog()
	})
}

// noteOversizedPacket follows the path MTU search while packets are being
// refused, and resizes the tunnel once the search has settled.
//
// The ICMP answer sent alongside only reaches the flows that act on it, so a
// path that cannot carry the tunnel has to be met by resizing it. Doing that on
// the first refusal would be wrong: discovery climbs, and what does not fit now
// may fit shortly. So the limit is watched instead of a clock, and the wait
// restarts every time it improves. A connection that cannot discover anything
// has nothing to wait for.
func (t *tunnel) noteOversizedPacket(size, fits int, discovering bool) {
	if fits <= 0 {
		return
	}
	t.oversizedReported.Do(func() {
		newError("a packet of ", size, " bytes does not fit a QUIC datagram on this path,",
			" which carries at most ", fits).AtWarning().WriteToLog()
	})

	now := time.Now()
	if fits > t.bestDatagramMTU {
		t.bestDatagramMTU = fits
		t.refusedSince = now
		return
	}
	if t.refusedSince.IsZero() {
		t.refusedSince = now
	}
	settle := pathMTUSettle
	if !discovering {
		settle = 0
	}
	if now.Sub(t.refusedSince) >= settle {
		t.outbound.lowerMTU(fits)
	}
}

// nextHopMTU reads the size advertised by an ICMP "packet too big" answer.
func nextHopMTU(packet []byte) int {
	switch {
	case len(packet) >= 28 && packet[0]>>4 == 4 && packet[20] == 3 && packet[21] == 4:
		// IPv4 header, then ICMP destination unreachable, fragmentation needed.
		return int(binary.BigEndian.Uint16(packet[26:28]))
	case len(packet) >= 48 && packet[0]>>4 == 6 && packet[40] == 2:
		// IPv6 header, then ICMPv6 packet too big.
		return int(binary.BigEndian.Uint32(packet[44:48]))
	}
	return 0
}

func waitPumps(wg *sync.WaitGroup) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(pumpShutdownGrace):
		newError("a tunnel pump did not stop in time, it will be serialized against the next cycle").AtDebug().WriteToLog()
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
