package netstack

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Every packet that passes through the device, either way, has to be handed
// back to gVisor's pools. One that is not still gets collected, so nothing
// leaks as far as Go is concerned, but each packet then costs a fresh buffer
// and the garbage collector has to clear up after it, which on the packet path
// of a tunnel is CPU, and battery, spent per packet for nothing.
func TestPacketsAreReturnedToThePool(t *testing.T) {
	refs.SetLeakMode(refs.LeaksPanic)
	defer refs.SetLeakMode(refs.NoLeakChecking)

	local := netip.MustParseAddr("172.16.0.2")
	peer := netip.MustParseAddr("172.16.0.1")
	device, _, _, err := CreateNetTUN([]netip.Addr{local}, 1280, false)
	if err != nil {
		t.Fatal(err)
	}

	// An echo request from the peer makes the stack answer, so a packet goes
	// in through Write and another comes out through Read.
	request := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)
	ip := header.IPv4(request)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(request)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(peer.As4()),
		DstAddr:     tcpip.AddrFrom4(local.As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	icmp := header.ICMPv4(request[header.IPv4MinimumSize:])
	icmp.SetType(header.ICMPv4Echo)
	icmp.SetChecksum(header.ICMPv4Checksum(icmp, 0))

	// The answer is handed over while Write is still delivering the request,
	// so it has to be read from elsewhere.
	answers := make(chan header.ICMPv4Type)
	go func() {
		defer close(answers)
		buffers, sizes := [][]byte{make([]byte, 1280)}, []int{0}
		for {
			if _, err := device.Read(buffers, sizes, 0); err != nil {
				return
			}
			answers <- header.ICMPv4(buffers[0][header.IPv4MinimumSize:sizes[0]]).Type()
		}
	}()
	for range 16 {
		if _, err := device.Write([][]byte{request}, 0); err != nil {
			t.Fatal(err)
		}
		if <-answers != header.ICMPv4EchoReply {
			t.Fatal("the stack did not answer the echo request")
		}
	}
	if err := device.Close(); err != nil {
		t.Fatal(err)
	}
	for range answers {
	}

	defer func() {
		if leaked := recover(); leaked != nil {
			t.Fatal(leaked)
		}
	}()
	refs.DoRepeatedLeakCheck()
}
