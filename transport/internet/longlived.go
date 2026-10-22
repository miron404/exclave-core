package internet

import (
	gonet "net"
	"time"
)

// Defaults for a TCP connection meant to sit idle for long stretches, such as
// a tunnel's single connection to its server.
const (
	// LongLivedKeepalive is how long such a connection may sit idle before
	// the kernel probes it, and what every dialed socket gets unless its
	// outbound says otherwise (see quietenIdleTCP). Go's default of 15
	// seconds is a radio wakeup four times a minute for every idle
	// connection on a phone; four minutes keeps the mapping of most carrier
	// NATs alive at a sixteenth of that.
	LongLivedKeepalive = 4 * time.Minute

	// LongLivedUserTimeout is how long sent data may go unacknowledged
	// before the kernel gives the connection up. It finds a path that died
	// while idle as soon as something is sent on it, and costs nothing while
	// nothing is, since it needs no timer of its own.
	LongLivedUserTimeout = 30 * time.Second

	longLivedKeepaliveRetry = 15 * time.Second
	longLivedKeepaliveCount = 3
)

// TCPConnOf digs the socket out of the wrappers the dialer and the security
// layers put around it, or returns nil when there is none, as for a
// connection through another outbound.
func TCPConnOf(conn gonet.Conn) *gonet.TCPConn {
	for conn != nil {
		switch c := conn.(type) {
		case *gonet.TCPConn:
			return c
		case *StatCouterConnection:
			conn = c.Connection
		case *trackedConn:
			conn = c.Conn
		case interface{ NetConn() gonet.Conn }:
			conn = c.NetConn()
		default:
			return nil
		}
	}
	return nil
}

// TuneLongLivedTCP sets how a long lived connection is kept and given up: a
// keepalive probe after keepalive of idling, none if it is zero, and the
// connection given up once sent data goes unacknowledged for userTimeout. It
// reports whether there was a socket to tune.
func TuneLongLivedTCP(conn gonet.Conn, keepalive, userTimeout time.Duration) (bool, error) {
	tcpConn := TCPConnOf(conn)
	if tcpConn == nil {
		return false, nil
	}
	var err error
	if keepalive > 0 {
		err = tcpConn.SetKeepAliveConfig(gonet.KeepAliveConfig{
			Enable:   true,
			Idle:     keepalive,
			Interval: longLivedKeepaliveRetry,
			Count:    longLivedKeepaliveCount,
		})
	} else {
		err = tcpConn.SetKeepAlive(false)
	}
	if err != nil {
		return true, err
	}
	if userTimeout > 0 {
		err = setTCPUserTimeout(tcpConn, userTimeout)
	}
	return true, err
}

// quietenIdleTCP gives a freshly dialed socket the long lived keepalive
// unless its outbound configured one. Go turns keepalive on for every socket
// it dials or wraps, at 15 seconds of idling, and both the core's dialer and
// the VPN's protected one take that default. A probe on a socket that sits
// idle is a radio wakeup, and through a VPN every connection an app keeps
// idle is one of these sockets, probed although the app never asked for it.
func quietenIdleTCP(conn gonet.Conn, sockopt *SocketConfig) {
	if sockopt != nil && (sockopt.TcpKeepAliveIdle != 0 || sockopt.TcpKeepAliveInterval != 0) {
		return
	}
	tcpConn, ok := conn.(*gonet.TCPConn)
	if !ok {
		return
	}
	_ = tcpConn.SetKeepAliveConfig(gonet.KeepAliveConfig{
		Enable:   true,
		Idle:     LongLivedKeepalive,
		Interval: longLivedKeepaliveRetry,
		Count:    longLivedKeepaliveCount,
	})
}
