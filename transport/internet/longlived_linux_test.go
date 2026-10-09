//go:build linux

package internet

import (
	"crypto/tls"
	gonet "net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/common/track"
)

type tlsWrapper struct{ *tls.Conn }

// A dialed connection reaches an outbound wrapped in the connection tracker
// and the byte counters, and often in TLS; the socket has to be found under
// all of them, or tuning it silently does nothing.
func TestTuneLongLivedTCPReachesTheSocket(t *testing.T) {
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

	pool := track.NewConnectionPool()
	for _, c := range []struct {
		name      string
		keepalive time.Duration
		wantOn    int
	}{
		{"default", LongLivedKeepalive, 1},
		{"off", 0, 0},
	} {
		raw, err := gonet.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		var conn net.Conn = &StatCouterConnection{Connection: newTrackedConn(raw, pool)}
		conn = tlsWrapper{tls.Client(conn, &tls.Config{})}

		tuned, err := TuneLongLivedTCP(conn, c.keepalive, LongLivedUserTimeout)
		if !tuned || err != nil {
			t.Fatalf("%s: tuned=%v err=%v", c.name, tuned, err)
		}
		sc, _ := raw.(*gonet.TCPConn).SyscallConn()
		_ = sc.Control(func(fd uintptr) {
			on, _ := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
			idle, _ := syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE)
			user, _ := syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)
			if on != c.wantOn {
				t.Errorf("%s: SO_KEEPALIVE is %d, want %d", c.name, on, c.wantOn)
			}
			if c.wantOn == 1 && idle != int(c.keepalive.Seconds()) {
				t.Errorf("%s: TCP_KEEPIDLE is %d", c.name, idle)
			}
			if user != int(LongLivedUserTimeout.Milliseconds()) {
				t.Errorf("%s: TCP_USER_TIMEOUT is %d", c.name, user)
			}
		})
		_ = raw.Close()
	}

	// Anything that is not a socket underneath is left alone.
	a, b := gonet.Pipe()
	defer a.Close()
	defer b.Close()
	if tuned, _ := TuneLongLivedTCP(a, LongLivedKeepalive, LongLivedUserTimeout); tuned {
		t.Error("a pipe was reported as tuned")
	}
}
