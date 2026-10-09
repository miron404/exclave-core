package masque

import (
	gonet "net"

	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

// tuneHTTP2Socket sets how the HTTP/2 connection is kept and given up: the
// profile's keepalive, and a user timeout that gives the connection up once
// sent data goes unacknowledged, which finds a path that died while idle as
// soon as something is sent on it. A connection through another outbound has
// no socket of its own here; the on-demand ping covers it instead.
func (o *Outbound) tuneHTTP2Socket(conn gonet.Conn) {
	tuned, err := internet.TuneLongLivedTCP(conn, o.tcpKeepalivePeriod, internet.LongLivedUserTimeout)
	switch {
	case err != nil:
		newError("failed to tune the HTTP/2 socket").Base(err).AtDebug().WriteToLog()
	case !tuned:
		newError("the HTTP/2 connection runs through another outbound, its socket is left as it is").AtDebug().WriteToLog()
	}
}
