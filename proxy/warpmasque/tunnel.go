package warpmasque

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
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
	// pumps to exit. They all give up as soon as the session is closed, so
	// this is only a guard against one that does not.
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

	// The address families the stack was brought up with. IPv6 is left off
	// when the MTU is below its minimum, whatever the device was assigned.
	hasIPv4, hasIPv6 bool

	// packets carries what the stack sends out, read from the device by a
	// single goroutine for the life of the tunnel. A pump waiting on it can
	// give up the moment its session ends, which a pump parked in a device
	// read could not: it held on until the next packet came and dropped that
	// one, so the packet that should have brought the session back was lost.
	// The channel is closed once the device is.
	packets    chan outgoingPacket
	bufferPool sync.Pool
	// carried holds a packet a pump took for a session that has ended, for
	// the next session to send first.
	carried chan outgoingPacket

	// Each of these reports once, so a condition that repeats per packet does
	// not fill the log.
	dropReported      sync.Once
	oversizedReported sync.Once

	// networkChanged carries a pending network change to the supervisor. It
	// holds at most one: two changes before the supervisor looks call for the
	// same response.
	networkChanged chan struct{}

	// pathGeneration moves whenever the session's path does, by a redial or
	// by a migration, and restarts the path MTU search.
	pathGeneration atomic.Uint32

	// Progress of the path MTU search. Only the reading pump touches these.
	searchGeneration uint32
	bestDatagramMTU  int
	refusedSince     time.Time
}

// outgoingPacket is one packet the stack sent, at buf[datagramContextIDHeadroom:]
// and n bytes long, in a buffer from the tunnel's pool.
type outgoingPacket struct {
	buf *[]byte
	n   int
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
		outbound: o,
		device:   device,
		net:      netStack,
		mtu:      o.mtu,
		cancel:   cancel,
		done:     make(chan struct{}),
		packets:  make(chan outgoingPacket),
		carried:  make(chan outgoingPacket, 1),

		networkChanged: make(chan struct{}, 1),
	}
	t.bufferPool.New = func() any {
		buf := make([]byte, t.mtu+datagramContextIDHeadroom)
		return &buf
	}
	for _, address := range addresses {
		if address.Is4() {
			t.hasIPv4 = true
		} else {
			t.hasIPv6 = true
		}
	}
	go t.readDevice(runCtx)
	go func() {
		defer close(t.done)
		t.maintain(runCtx, o, dialer)
	}()
	return t, nil
}

// NetworkChanged tells the tunnel that the device moved to another network. The
// session follows it if it can, and is redialed otherwise; the stack, and every
// connection on it, is kept either way.
func (t *tunnel) NetworkChanged() {
	select {
	case t.networkChanged <- struct{}{}:
	default:
	}
}

func (t *tunnel) Close() error {
	t.cancel()
	err := t.device.Close()
	<-t.done
	return err
}

// carries reports whether the stack has an address of the family addr needs.
func (t *tunnel) carries(addr netip.Addr) bool {
	if addr.Is4() {
		return t.hasIPv4
	}
	return t.hasIPv6
}

func (t *tunnel) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return t.net.DialContextTCPAddrPort(ctx, addr)
}

func (t *tunnel) DialUDPAddrPort(laddr, raddr netip.AddrPort) (net.Conn, error) {
	return t.net.DialUDPAddrPort(laddr, raddr)
}

// readDevice reads what the stack sends out and hands it to whichever of the
// supervisor or the outgoing pump is waiting, until the device is closed.
func (t *tunnel) readDevice(ctx context.Context) {
	defer close(t.packets)
	buffers := make([][]byte, 1)
	sizes := make([]int, 1)
	for {
		bufPtr := t.bufferPool.Get().(*[]byte)
		buffers[0], sizes[0] = (*bufPtr)[datagramContextIDHeadroom:], 0
		_, err := t.device.Read(buffers, sizes, 0)
		buffers[0] = nil
		if err != nil {
			// The device only fails once it is closed.
			t.bufferPool.Put(bufPtr)
			if ctx.Err() == nil {
				newError("failed to read from the virtual network stack").Base(err).AtWarning().WriteToLog()
			}
			return
		}
		select {
		case t.packets <- outgoingPacket{buf: bufPtr, n: sizes[0]}:
		case <-ctx.Done():
			t.bufferPool.Put(bufPtr)
			return
		}
	}
}

// release hands a packet's buffer back to the pool.
func (t *tunnel) release(p outgoingPacket) {
	if p.buf != nil {
		t.bufferPool.Put(p.buf)
	}
}

// carry keeps p for the next session. Only one is kept: by the time a
// session is up again, anything older has been retransmitted anyway.
func (t *tunnel) carry(p outgoingPacket) {
	select {
	case old := <-t.carried:
		t.release(old)
	default:
	}
	t.carried <- p
}

// takeCarried returns the packet kept for the next session, if any.
func (t *tunnel) takeCarried() (outgoingPacket, bool) {
	select {
	case p := <-t.carried:
		return p, true
	default:
		return outgoingPacket{}, false
	}
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
// A session is only ever dialed for a packet that something inside the stack
// wants to send, and that packet is the first the new session carries. So a
// tunnel that broke while idle stays down, at no cost, until it is used again,
// and one whose endpoint cannot be reached, a network that blocks it or no
// network at all, tries again only while something still asks for it, never
// more often than the backoff allows, instead of on a timer for as long as the
// tunnel exists.
func (t *tunnel) maintain(ctx context.Context, o *Outbound, dialer internet.Dialer) {
	backoff := reconnectDelayMin
	// nextDial is the earliest a dial may be tried after one failed.
	var nextDial time.Time
	var pending outgoingPacket

	for {
		if ctx.Err() != nil {
			t.release(pending)
			return
		}

		if pending.buf == nil {
			var ok bool
			if pending, ok = t.takeCarried(); !ok {
				changed, open := t.waitForPacket(ctx, &pending)
				if !open {
					return
				}
				if changed {
					// What failed on the old network says nothing about
					// the new one.
					backoff, nextDial = reconnectDelayMin, time.Time{}
					continue
				}
			}
		}

		if wait := time.Until(nextDial); wait > 0 {
			changed, open := t.holdUntil(ctx, wait, &pending)
			if !open {
				t.release(pending)
				return
			}
			if changed {
				backoff = reconnectDelayMin
			}
			nextDial = time.Time{}
		}

		// The HTTP/2 transport keeps its request open for as long as the tunnel
		// lives, so the dial context cannot simply be cancelled once the dial
		// returns; it is handed to the session and released with it. Until then
		// a timer bounds how long the setup may take.
		// A dial is made on whatever network is current, so a change reported
		// before it is already answered by it.
		t.takeNetworkChange()
		dialCtx, cancelDial := context.WithCancel(ctx)
		dialTimer := time.AfterFunc(dialTimeout, cancelDial)
		sess, err := o.dial(dialCtx, dialer)
		timedOut := !dialTimer.Stop()
		if err != nil {
			cancelDial()
			if ctx.Err() != nil {
				t.release(pending)
				return
			}
			if timedOut {
				err = newError("timed out after ", dialTimeout).Base(err)
			}
			newError("failed to establish the MASQUE tunnel").Base(err).AtWarning().WriteToLog()
			// The packet is stale by the time another dial may be tried;
			// whatever still wants out will send again, and that is what
			// the next attempt waits for.
			t.release(pending)
			pending = outgoingPacket{}
			nextDial = time.Now().Add(backoff)
			backoff = min(backoff*2, reconnectDelayMax)
			continue
		}
		sess.cancel = cancelDial
		backoff = reconnectDelayMin
		newError("MASQUE tunnel established").AtInfo().WriteToLog()

		if _, err := sess.ipConn.WritePacketBuffer(*pending.buf, datagramContextIDHeadroom, pending.n); err != nil {
			newError("failed to send the first packet").Base(err).AtDebug().WriteToLog()
		}
		t.release(pending)
		pending = outgoingPacket{}

		errChan := make(chan error, 2)
		pumpCtx, cancelPumps := context.WithCancel(ctx)
		var wg sync.WaitGroup
		wg.Add(2)
		// A new connection starts its own search.
		t.pathGeneration.Add(1)
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
			errChan <- t.pumpToTunnel(pumpCtx, sess, icmpQueue)
		}()
		go func() {
			defer wg.Done()
			errChan <- t.pumpFromTunnel(sess, o.useHTTP2)
		}()

		err = t.followSession(ctx, o, dialer, sess, errChan)
		cancelPumps()
		sess.Close()
		if ctx.Err() != nil {
			return
		}
		newError("MASQUE tunnel lost, reconnecting").Base(err).AtInfo().WriteToLog()
		waitPumps(&wg)
	}
}

// waitForPacket waits for something to send and leaves it in p. It reports
// whether the network changed meanwhile, which ends the wait with nothing in p,
// and whether the tunnel is still open.
func (t *tunnel) waitForPacket(ctx context.Context, p *outgoingPacket) (changed, open bool) {
	select {
	case <-ctx.Done():
		return false, false
	case <-t.networkChanged:
		return true, true
	case packet, ok := <-t.packets:
		if !ok {
			return false, false
		}
		*p = packet
		return false, true
	}
}

// holdUntil waits out a backoff of d with a packet in hand, or less if the
// network changes. The stack is drained meanwhile so that it is not held up,
// and the newest packet is the one kept.
func (t *tunnel) holdUntil(ctx context.Context, d time.Duration, p *outgoingPacket) (changed, open bool) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, false
		case <-t.networkChanged:
			return true, true
		case <-timer.C:
			return false, true
		case packet, ok := <-t.packets:
			if !ok {
				return false, false
			}
			t.release(*p)
			*p = packet
		}
	}
}

// followSession waits for the session to end, moving it onto the new network
// each time the device changes networks. A session that cannot move ends
// there, and the supervisor redials it once something wants to send, which on
// an idle tunnel costs nothing until then.
func (t *tunnel) followSession(ctx context.Context, o *Outbound, dialer internet.Dialer, sess *ipSession, errChan <-chan error) error {
	for {
		select {
		case err := <-errChan:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-t.networkChanged:
			if err := o.migrate(ctx, dialer, sess); err != nil {
				return newError("the network changed and the connection could not follow").Base(err)
			}
			// The new path starts its MTU search from the initial packet size.
			t.pathGeneration.Add(1)
		}
	}
}

// takeNetworkChange clears a pending network change.
func (t *tunnel) takeNetworkChange() {
	select {
	case <-t.networkChanged:
	default:
	}
}

// pumpToTunnel forwards packets from the stack into the CONNECT-IP session and
// injects any ICMP error the session generates back into the stack.
//
// A packet taken for a session that has ended, or one the session could not
// send because it had just closed, is carried over to the next session rather
// than dropped: it is what wants that session.
func (t *tunnel) pumpToTunnel(ctx context.Context, sess *ipSession, icmpQueue chan<- []byte) error {
	for {
		var p outgoingPacket
		select {
		case <-ctx.Done():
			return ctx.Err()
		case packet, ok := <-t.packets:
			if !ok {
				return os.ErrClosed
			}
			p = packet
		}
		if ctx.Err() != nil {
			t.carry(p)
			return ctx.Err()
		}
		icmp, err := sess.ipConn.WritePacketBuffer(*p.buf, datagramContextIDHeadroom, p.n)
		if err == nil && len(icmp) == 0 {
			// An ICMP answer means the packet was refused, not sent.
			sess.counters.addWrite(p.n)
			sess.liveness.sent()
		}
		if err != nil {
			if errors.As(err, new(*connectip.CloseError)) {
				t.carry(p)
				return err
			}
			t.release(p)
			// A single rejected packet must not take the tunnel down, but it is
			// worth saying why once: a packet that never fits is an MTU that is
			// too high for the path, and it stalls everything except the
			// smallest exchanges.
			t.reportDroppedPacket(p.n, err)
			continue
		}
		t.release(p)
		if len(icmp) > 0 {
			// The packet did not fit a datagram on this path. The answer is an
			// ICMP "packet too big" naming the size that does fit, which makes
			// the stack shrink that one flow. That only helps flows that honour
			// it, so the size is also remembered for the tunnel as a whole.
			t.noteOversizedPacket(p.n, nextHopMTU(icmp), sess.canDiscoverPathMTU)
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
		sess.liveness.heard()
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

	if generation := t.pathGeneration.Load(); generation != t.searchGeneration {
		// The path changed under the search, so what it learned is void.
		t.searchGeneration = generation
		t.bestDatagramMTU, t.refusedSince = 0, time.Time{}
	}
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
