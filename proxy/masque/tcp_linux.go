//go:build linux

package masque

import (
	gonet "net"
	"time"

	"golang.org/x/sys/unix"
)

func setTCPUserTimeout(conn *gonet.TCPConn, timeout time.Duration) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, int(timeout.Milliseconds()))
	}); err != nil {
		return err
	}
	return sockErr
}
