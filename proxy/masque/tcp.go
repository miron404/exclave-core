package masque

import (
	gonet "net"
	"time"

	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

const (
	// tcpKeepaliveRetry and tcpKeepaliveCount are how an unanswered keepalive
	// probe is retried before the connection is given up.
	tcpKeepaliveRetry = 15 * time.Second
	tcpKeepaliveCount = 3

	// tcpUserTimeout is how long data sent on the HTTP/2 connection may go
	// unacknowledged before the kernel gives the connection up. It is what
	// finds a path that died while idle, as soon as something is sent on it,
	// and costs nothing while nothing is: unlike a ping, it needs no timer of
	// its own. The tunnel then redials, instead of both pumps waiting on a
	// connection that will never deliver again.
	tcpUserTimeout = 30 * time.Second
)

// tuneHTTP2Socket sets how the HTTP/2 connection is kept and given up. It only
// applies to a real socket: a connection through another outbound is that
// outbound's to manage.
func (o *Outbound) tuneHTTP2Socket(conn gonet.Conn) {
	if statConn, ok := conn.(*internet.StatCouterConnection); ok {
		conn = statConn.Connection
	}
	tcpConn, ok := conn.(*gonet.TCPConn)
	if !ok {
		return
	}
	var err error
	if o.tcpKeepalivePeriod > 0 {
		err = tcpConn.SetKeepAliveConfig(gonet.KeepAliveConfig{
			Enable:   true,
			Idle:     o.tcpKeepalivePeriod,
			Interval: tcpKeepaliveRetry,
			Count:    tcpKeepaliveCount,
		})
	} else {
		err = tcpConn.SetKeepAlive(false)
	}
	if err != nil {
		newError("failed to set TCP keepalive").Base(err).AtDebug().WriteToLog()
	}
	if err := setTCPUserTimeout(tcpConn, tcpUserTimeout); err != nil {
		newError("failed to set TCP user timeout").Base(err).AtDebug().WriteToLog()
	}
}
