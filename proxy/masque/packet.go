package masque

import (
	"sync"

	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	"github.com/exclavenetwork/exclave-core/v5/common/net"
)

// newPacketReader tags every inbound datagram with the endpoint it came from,
// restoring the original domain when the request was made for one.
func newPacketReader(conn net.Conn, ipToDomain *sync.Map) buf.Reader {
	packetConn, ok := conn.(net.PacketConn)
	if !ok {
		return buf.NewReader(conn)
	}
	return &packetReader{packetConn: packetConn, ipToDomain: ipToDomain}
}

type packetReader struct {
	packetConn net.PacketConn
	ipToDomain *sync.Map
}

func (r *packetReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	n, src, err := r.packetConn.ReadFrom(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))
	udpAddr, ok := src.(*net.UDPAddr)
	if !ok {
		b.Release()
		return nil, newError("unexpected source address type")
	}
	b.Endpoint = &net.Destination{
		Address: net.IPAddress(udpAddr.IP),
		Port:    net.Port(udpAddr.Port),
		Network: net.Network_UDP,
	}
	if domain, ok := r.ipToDomain.Load(udpAddr.AddrPort().Addr()); ok {
		b.Endpoint.Address = domain.(net.Address)
	}
	return buf.MultiBuffer{b}, nil
}

// newPacketWriter resolves per-packet destinations, so a single UDP session can
// address more than the destination the outbound was opened for.
func newPacketWriter(conn net.Conn, o *Outbound, originalDestination, destination net.Destination, ipToDomain *sync.Map) buf.Writer {
	packetConn, ok := conn.(net.PacketConn)
	if !ok {
		return buf.NewWriter(conn)
	}
	return &packetWriter{
		packetConn:          packetConn,
		outbound:            o,
		originalDestination: originalDestination,
		destination:         destination,
		ipToDomain:          ipToDomain,
	}
}

type packetWriter struct {
	packetConn          net.PacketConn
	outbound            *Outbound
	originalDestination net.Destination
	destination         net.Destination
	ipToDomain          *sync.Map
}

func (w *packetWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		if b == nil {
			continue
		}
		originalDestination, destination := w.originalDestination, w.destination
		if b.Endpoint != nil {
			originalDestination, destination = *b.Endpoint, *b.Endpoint
			if destination.Address.Family().IsDomain() &&
				w.originalDestination.Address.Family().IsDomain() &&
				destination.Address.Domain() == w.originalDestination.Address.Domain() {
				// Already resolved when the session was opened.
				destination.Address = w.destination.Address
			} else {
				resolved, err := w.outbound.resolve(destination)
				if err != nil {
					return err
				}
				destination = resolved
			}
		}
		udpAddr := &net.UDPAddr{IP: destination.Address.IP(), Port: int(destination.Port)}
		if originalDestination.Address.Family().IsDomain() {
			w.ipToDomain.LoadOrStore(udpAddr.AddrPort().Addr(), originalDestination.Address)
		}
		if _, err := w.packetConn.WriteTo(b.Bytes(), udpAddr); err != nil {
			return err
		}
	}
	return nil
}
