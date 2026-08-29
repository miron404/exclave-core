package masque

import (
	"context"
	gonet "net"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/features/stats"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

// socketCounters are the byte counters the core attaches to a dialed
// connection. The socket is handed to quic-go unwrapped, so the tunnel feeds
// these itself.
type socketCounters struct {
	read  stats.Counter
	write stats.Counter
}

func (c *socketCounters) addRead(n int) {
	if c != nil && c.read != nil {
		c.read.Add(int64(n))
	}
}

func (c *socketCounters) addWrite(n int) {
	if c != nil && c.write != nil {
		c.write.Add(int64(n))
	}
}

// listenPacket obtains the UDP socket the QUIC connection runs on.
//
// The bool reports whether the result is a real socket, and therefore whether
// the connection can discover the path MTU.
func listenPacket(ctx context.Context, dialer internet.Dialer, destination net.Destination, endpoint gonet.Addr) (gonet.PacketConn, *socketCounters, bool, error) {
	conn, err := dialer.Dial(ctx, destination)
	if err != nil {
		return nil, nil, false, err
	}
	packetConn, counters, ok := unwrapPacketConn(conn)
	if !ok {
		// A chained outbound is not a socket. Datagrams still flow, but the
		// path MTU cannot be discovered.
		return &endpointPacketConn{Conn: conn, endpoint: endpoint}, counters, false, nil
	}
	return packetConn, counters, true, nil
}

// unwrapPacketConn digs the socket out of the core's connection wrappers.
//
// quic-go decides whether it can set the "don't fragment" bit, and so whether
// to discover the path MTU, from the methods the socket itself carries:
//
//	if !c.config.DisablePathMTUDiscovery && c.conn.capabilities().DF {
//	    c.mtuDiscoverer.Start(now)
//	}
//
// Anything in the way hides that, the packet size then stays at the initial
// 1280 for the life of the connection, and a full size tunnel packet no longer
// fits a datagram. Wrapping it back up to count bytes does not work either: the
// out of band read path goes through golang.org/x/net/ipv4 straight to the
// socket. So the socket is passed on untouched and the counters come back
// separately, for the tunnel to feed.
func unwrapPacketConn(conn net.Conn) (gonet.PacketConn, *socketCounters, bool) {
	counters := &socketCounters{}
	inner := conn
	if statConn, ok := inner.(*internet.StatCouterConnection); ok {
		inner = statConn.Connection
		counters.read = statConn.ReadCounter
		counters.write = statConn.WriteCounter
	}
	switch c := inner.(type) {
	case *internet.PacketConnWrapper:
		return c.Conn, counters, true
	case gonet.PacketConn:
		return c, counters, true
	}
	return nil, counters, false
}
