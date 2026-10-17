package masque

import (
	"sync"

	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/features/dns"
)

var (
	_ buf.Writer = (*packetReaderWriter)(nil)
	_ buf.Reader = (*packetReaderWriter)(nil)
)

func (r *packetReaderWriter) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	n, src, err := r.conn.ReadFrom(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))
	b.Endpoint = &net.Destination{
		Address: net.IPAddress(src.(*net.UDPAddr).IP),
		Port:    net.Port(src.(*net.UDPAddr).Port),
		Network: net.Network_UDP,
	}
	if domain, ok := r.ipToDomain.Load(src.(*net.UDPAddr).AddrPort().Addr()); ok {
		b.Endpoint.Address = domain.(net.Address)
	}
	return buf.MultiBuffer{b}, nil
}

func newPacketReaderWriter(conn net.PacketConn, originalDest, dest net.Destination, dns dns.Client, domainStrategy ClientConfig_DomainStrategy, hasIPv4, hasIPv6 bool) *packetReaderWriter {
	return &packetReaderWriter{
		conn:           conn,
		originalDest:   originalDest,
		dest:           dest,
		dns:            dns,
		domainStrategy: domainStrategy,
		hasIPv4:        hasIPv4,
		hasIPv6:        hasIPv6,
	}
}

type packetReaderWriter struct {
	conn           net.PacketConn
	originalDest   net.Destination
	dest           net.Destination
	dns            dns.Client
	domainStrategy ClientConfig_DomainStrategy
	hasIPv4        bool
	hasIPv6        bool
	ipToDomain     sync.Map
}

func (w *packetReaderWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		if b == nil {
			continue
		}
		originalDest, dest := w.originalDest, w.dest
		if b.Endpoint != nil {
			originalDest, dest = *b.Endpoint, *b.Endpoint
		}
		if dest.Address.Family().IsDomain() {
			if w.originalDest.Address.Family().IsDomain() && dest.Address.Domain() == w.originalDest.Address.Domain() {
				dest.Address = w.dest.Address
			} else {
				ips, err := dns.LookupIPWithOption(w.dns, dest.Address.Domain(), dns.IPOption{
					IPv4Enable: w.hasIPv4 && w.domainStrategy != ClientConfig_USE_IP6,
					IPv6Enable: w.hasIPv6 && w.domainStrategy != ClientConfig_USE_IP4,
				})
				if err != nil {
					return newError("failed to lookup DNS").Base(err)
				} else if len(ips) == 0 {
					return dns.ErrEmptyResponse
				}
				if w.domainStrategy == ClientConfig_PREFER_IP4 || w.domainStrategy == ClientConfig_PREFER_IP6 {
					for _, ip := range ips {
						if ip.To4() != nil == (w.domainStrategy == ClientConfig_PREFER_IP4) {
							dest.Address = net.IPAddress(ip)
						}
					}
				} else {
					dest.Address = net.IPAddress(ips[0])
				}
			}
		}
		udpAddr := &net.UDPAddr{
			IP:   dest.Address.IP(),
			Port: int(dest.Port),
		}
		if originalDest.Address.Family().IsDomain() {
			w.ipToDomain.LoadOrStore(udpAddr.AddrPort().Addr(), originalDest.Address)
		}
		_, err := w.conn.WriteTo(b.Bytes(), udpAddr)
		if err != nil {
			return err
		}
	}
	return nil
}
