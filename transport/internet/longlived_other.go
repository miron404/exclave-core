//go:build !linux

package internet

import (
	gonet "net"
	"time"
)

func setTCPUserTimeout(*gonet.TCPConn, time.Duration) error { return nil }
