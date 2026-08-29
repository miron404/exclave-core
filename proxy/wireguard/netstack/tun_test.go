package netstack

import (
	"net"
	"net/netip"
	"sync"
	"testing"
)

// Closing the device while connections on the stack are sending through it
// must not panic. This covers the shape of the crash reported from a device --
// "send on closed channel" out of WriteNotify -- though not its timing: the
// window between the stack picking a packet up and handing it over is narrow,
// and the teardown usually stops senders before they reach it. The fix does not
// depend on that window, it stops closing the channel the stack delivers on.
func TestCloseWhileTrafficIsFlowing(t *testing.T) {
	for range 50 {
		device, netStack, _, err := CreateNetTUN(
			[]netip.Addr{netip.MustParseAddr("172.16.0.2")}, 1280, false,
		)
		if err != nil {
			t.Fatal(err)
		}

		var workers sync.WaitGroup
		workers.Add(1)
		go func() {
			defer workers.Done()
			buffers := [][]byte{make([]byte, 1280)}
			sizes := []int{0}
			for {
				if _, err := device.Read(buffers, sizes, 0); err != nil {
					return
				}
			}
		}()

		conn, err := netStack.DialUDPAddrPort(netip.MustParseAddrPort("172.16.0.2:0"), netip.AddrPort{})
		if err != nil {
			t.Fatal(err)
		}
		// The conn is unconnected, as the tunnel's own writer leaves it, so
		// each packet carries its destination.
		destination := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}
		for range 8 {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for range 200 {
					if _, err := conn.WriteTo([]byte("probe"), destination); err != nil {
						return
					}
				}
			}()
		}

		if err := device.Close(); err != nil {
			t.Fatal(err)
		}
		workers.Wait()
		_ = conn.Close()
	}
}
