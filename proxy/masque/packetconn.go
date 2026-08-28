package masque

import (
	"context"
	gonet "net"
	"syscall"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/features/stats"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

// listenPacket obtains the UDP socket the QUIC connection runs on.
//
// It unwraps the core's own packet conn rather than going through singbridge.
// That wrapper deliberately hides the socket's syscall.Conn, and quic-go uses
// exactly that to decide whether it can set the "don't fragment" bit:
//
//	if !c.config.DisablePathMTUDiscovery && c.conn.capabilities().DF {
//	    c.mtuDiscoverer.Start(now)
//	}
//
// With it hidden, path MTU discovery never starts, the packet size stays at the
// initial 1280 for the life of the connection, and a full size tunnel packet no
// longer fits a datagram. Traffic accounting is kept by counting here instead.
//
// The bool reports whether the result is a real socket, and therefore whether
// the connection can discover the path MTU at all.
func listenPacket(ctx context.Context, dialer internet.Dialer, destination net.Destination, endpoint gonet.Addr) (gonet.PacketConn, bool, error) {
	conn, err := dialer.Dial(ctx, destination)
	if err != nil {
		return nil, false, err
	}

	var readCounter, writeCounter stats.Counter
	inner := net.Conn(conn)
	if statConn, ok := inner.(*internet.StatCouterConnection); ok {
		inner = statConn.Connection
		readCounter = statConn.ReadCounter
		writeCounter = statConn.WriteCounter
	}

	var packetConn gonet.PacketConn
	switch c := inner.(type) {
	case *internet.PacketConnWrapper:
		packetConn = c.Conn
	case gonet.PacketConn:
		packetConn = c
	default:
		// A chained outbound is not a socket. Datagrams still flow, but the
		// path MTU cannot be discovered.
		return &endpointPacketConn{Conn: conn, endpoint: endpoint}, false, nil
	}

	if readCounter == nil && writeCounter == nil {
		return packetConn, true, nil
	}
	return &countingPacketConn{PacketConn: packetConn, read: readCounter, write: writeCounter}, true, nil
}

// countingPacketConn counts traffic while leaving the socket visible. Every
// method quic-go looks for is forwarded, so it still enables the "don't
// fragment" bit, the OOB read path and the socket buffer sizes.
type countingPacketConn struct {
	gonet.PacketConn
	read  stats.Counter
	write stats.Counter
}

func (c *countingPacketConn) count(counter stats.Counter, n int) {
	if counter != nil {
		counter.Add(int64(n))
	}
}

func (c *countingPacketConn) ReadFrom(p []byte) (int, gonet.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	c.count(c.read, n)
	return n, addr, err
}

func (c *countingPacketConn) WriteTo(p []byte, addr gonet.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	c.count(c.write, n)
	return n, err
}

func (c *countingPacketConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *gonet.UDPAddr, err error) {
	udpConn, ok := c.PacketConn.(*gonet.UDPConn)
	if !ok {
		return 0, 0, 0, nil, syscall.EINVAL
	}
	n, oobn, flags, addr, err = udpConn.ReadMsgUDP(b, oob)
	c.count(c.read, n)
	return
}

func (c *countingPacketConn) WriteMsgUDP(b, oob []byte, addr *gonet.UDPAddr) (n, oobn int, err error) {
	udpConn, ok := c.PacketConn.(*gonet.UDPConn)
	if !ok {
		return 0, 0, syscall.EINVAL
	}
	n, oobn, err = udpConn.WriteMsgUDP(b, oob, addr)
	c.count(c.write, n)
	return
}

func (c *countingPacketConn) SyscallConn() (syscall.RawConn, error) {
	syscallConn, ok := c.PacketConn.(syscall.Conn)
	if !ok {
		return nil, syscall.EINVAL
	}
	return syscallConn.SyscallConn()
}

func (c *countingPacketConn) SetReadBuffer(bytes int) error {
	if setter, ok := c.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return setter.SetReadBuffer(bytes)
	}
	return syscall.EINVAL
}

func (c *countingPacketConn) SetWriteBuffer(bytes int) error {
	if setter, ok := c.PacketConn.(interface{ SetWriteBuffer(int) error }); ok {
		return setter.SetWriteBuffer(bytes)
	}
	return syscall.EINVAL
}
