//go:build !linux

package masque

import (
	gonet "net"
	"time"
)

func setTCPUserTimeout(*gonet.TCPConn, time.Duration) error { return nil }
