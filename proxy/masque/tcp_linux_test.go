//go:build linux

package masque

import (
	gonet "net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

// The core dialer leaves Go's default TCP keepalive on every socket, a probe
// after 15 seconds of idling and every 15 seconds after, which is a radio
// wakeup four times a minute on an idle phone. The HTTP/2 connection sets its
// own, and a user timeout that gives up a connection whose sent data goes
// unacknowledged.
func TestHTTP2SocketIsTuned(t *testing.T) {
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()

	for _, c := range []struct {
		period    time.Duration
		keepalive int
		idle      int
	}{
		{defaultTCPKeepalivePeriod, 1, 240},
		{90 * time.Second, 1, 90},
		{0, 0, -1},
	} {
		dialed, err := gonet.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		// Wrapped the way the core dialer hands it over.
		conn := &internet.StatCouterConnection{Connection: dialed}
		(&Outbound{tcpKeepalivePeriod: c.period}).tuneHTTP2Socket(conn)

		raw, _ := dialed.(*gonet.TCPConn).SyscallConn()
		_ = raw.Control(func(fd uintptr) {
			keepalive, _ := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
			idle, _ := syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE)
			userTimeout, _ := syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)
			if keepalive != c.keepalive {
				t.Errorf("period %v: SO_KEEPALIVE is %d, want %d", c.period, keepalive, c.keepalive)
			}
			if c.idle >= 0 && idle != c.idle {
				t.Errorf("period %v: TCP_KEEPIDLE is %ds, want %ds", c.period, idle, c.idle)
			}
			if userTimeout != int(internet.LongLivedUserTimeout.Milliseconds()) {
				t.Errorf("period %v: TCP_USER_TIMEOUT is %dms", c.period, userTimeout)
			}
		})
		_ = dialed.Close()
	}
}
