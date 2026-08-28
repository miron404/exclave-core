package masque

//go:generate go run github.com/exclavenetwork/exclave-core/v5/common/errors/errorgen

import (
	"context"
	"crypto/ecdsa"
	"net/netip"
	"sync"
	"time"

	core "github.com/exclavenetwork/exclave-core/v5"
	"github.com/exclavenetwork/exclave-core/v5/common"
	"github.com/exclavenetwork/exclave-core/v5/common/buf"
	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/common/session"
	"github.com/exclavenetwork/exclave-core/v5/common/signal"
	"github.com/exclavenetwork/exclave-core/v5/common/task"
	"github.com/exclavenetwork/exclave-core/v5/features/dns"
	"github.com/exclavenetwork/exclave-core/v5/features/policy"
	"github.com/exclavenetwork/exclave-core/v5/proxy"
	"github.com/exclavenetwork/exclave-core/v5/transport"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}

var (
	_ proxy.Outbound                    = (*Outbound)(nil)
	_ proxy.ClosableOutbound            = (*Outbound)(nil)
	_ proxy.OutboundWithInterfaceUpdate = (*Outbound)(nil)
)

// Outbound proxies traffic through a MASQUE CONNECT-IP tunnel.
type Outbound struct {
	serverAddress     net.Address
	http2Address      net.Address
	serverPort        net.Port
	serverName        string
	useHTTP2          bool
	mtu               int
	keepalivePeriod   time.Duration
	initialPacketSize uint16
	domainStrategy    ClientConfig_DomainStrategy

	privateKey        *ecdsa.PrivateKey
	endpointPublicKey *ecdsa.PublicKey

	localAddresses []netip.Addr
	hasIPv4        bool
	hasIPv6        bool

	policyManager policy.Manager
	dns           dns.Client

	tunnelAccess sync.Mutex
	tunnel       *tunnel
}

func NewClient(ctx context.Context, config *ClientConfig) (*Outbound, error) {
	if config.Address == nil {
		return nil, newError("endpoint address is not specified")
	}
	if config.Port == 0 || config.Port > 65535 {
		return nil, newError("invalid endpoint port: ", config.Port)
	}
	privateKey, err := parsePrivateKey(config.PrivateKey)
	if err != nil {
		return nil, err
	}
	var endpointPublicKey *ecdsa.PublicKey
	if !config.AllowInsecure {
		if endpointPublicKey, err = parseEndpointPublicKey(config.EndpointPublicKey); err != nil {
			return nil, err
		}
	}
	o := &Outbound{
		serverAddress:     config.Address.AsAddress(),
		serverPort:        net.Port(config.Port),
		serverName:        config.ServerName,
		useHTTP2:          config.UseHttp2,
		mtu:               int(config.Mtu),
		keepalivePeriod:   time.Duration(config.KeepalivePeriod) * time.Second,
		initialPacketSize: uint16(config.InitialPacketSize),
		domainStrategy:    config.DomainStrategy,
		privateKey:        privateKey,
		endpointPublicKey: endpointPublicKey,
	}
	if config.Http2Address != nil {
		o.http2Address = config.Http2Address.AsAddress()
	}
	if o.serverName == "" {
		o.serverName = DefaultServerName
	}
	if o.mtu <= 0 {
		o.mtu = defaultMTU
	}
	if o.keepalivePeriod <= 0 {
		o.keepalivePeriod = defaultKeepalivePeriod
	}
	for _, address := range config.LocalAddress {
		addr, err := netip.ParseAddr(address)
		if err != nil {
			return nil, newError("failed to parse the assigned address ", address).Base(err)
		}
		o.localAddresses = append(o.localAddresses, addr)
		if addr.Is4() {
			o.hasIPv4 = true
		} else {
			o.hasIPv6 = true
		}
	}
	if len(o.localAddresses) == 0 {
		return nil, newError("no address is assigned to the tunnel")
	}
	v := core.MustFromContext(ctx)
	o.policyManager = v.GetFeature(policy.ManagerType()).(policy.Manager)
	o.dns = v.GetFeature(dns.ClientType()).(dns.Client)
	return o, nil
}

// endpoint returns the destination the tunnel connects to for the active mode.
func (o *Outbound) endpoint(network net.Network) net.Destination {
	address := o.serverAddress
	if o.useHTTP2 && o.http2Address != nil {
		address = o.http2Address
	}
	return net.Destination{Address: address, Port: o.serverPort, Network: network}
}

func (o *Outbound) getTunnel(ctx context.Context, dialer internet.Dialer) (*tunnel, error) {
	o.tunnelAccess.Lock()
	defer o.tunnelAccess.Unlock()
	if o.tunnel != nil {
		return o.tunnel, nil
	}
	t, err := newTunnel(core.ToBackgroundDetachedContext(ctx), o, dialer)
	if err != nil {
		return nil, err
	}
	o.tunnel = t
	return t, nil
}

// InterfaceUpdate drops the tunnel when the underlying network changes, so the
// next request rebuilds it over the new interface.
func (o *Outbound) InterfaceUpdate() {
	_ = o.Close()
}

func (o *Outbound) Close() error {
	o.tunnelAccess.Lock()
	t := o.tunnel
	o.tunnel = nil
	o.tunnelAccess.Unlock()
	if t != nil {
		// Closing tears down a live session and waits for its pumps, which can
		// block for as long as the shutdown grace period.
		go func() {
			_ = t.Close()
		}()
	}
	return nil
}

// resolve maps a domain destination onto an address reachable inside the
// tunnel, honouring the configured domain strategy.
func (o *Outbound) resolve(destination net.Destination) (net.Destination, error) {
	if !destination.Address.Family().IsDomain() {
		return destination, nil
	}
	ips, err := dns.LookupIPWithOption(o.dns, destination.Address.Domain(), dns.IPOption{
		IPv4Enable: o.hasIPv4 && o.domainStrategy != ClientConfig_USE_IP6,
		IPv6Enable: o.hasIPv6 && o.domainStrategy != ClientConfig_USE_IP4,
	})
	if err != nil {
		return destination, newError("failed to look up ", destination.Address.Domain()).Base(err)
	}
	if len(ips) == 0 {
		return destination, dns.ErrEmptyResponse
	}
	resolved := destination
	resolved.Address = net.IPAddress(ips[0])
	if o.domainStrategy == ClientConfig_PREFER_IP4 || o.domainStrategy == ClientConfig_PREFER_IP6 {
		preferIPv4 := o.domainStrategy == ClientConfig_PREFER_IP4
		for _, ip := range ips {
			if (ip.To4() != nil) == preferIPv4 {
				resolved.Address = net.IPAddress(ip)
				break
			}
		}
	}
	return resolved, nil
}

// Process implements proxy.Outbound.
func (o *Outbound) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}
	originalDestination := outbound.Target

	tunnel, err := o.getTunnel(ctx, dialer)
	if err != nil {
		return err
	}

	destination, err := o.resolve(originalDestination)
	if err != nil {
		return err
	}

	newError("tunneling request to ", originalDestination, " via ", o.endpoint(net.Network_Unknown).NetAddr()).
		WriteToLog(session.ExportIDToError(ctx))

	p := o.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, p.Timeouts.ConnectionIdle)

	addrPort := netip.AddrPortFrom(toNetIPAddr(destination.Address), destination.Port.Value())
	var requestFunc func() error
	var responseFunc func() error

	if destination.Network == net.Network_TCP {
		conn, err := tunnel.DialContextTCPAddrPort(ctx, addrPort)
		if err != nil {
			return newError("failed to open a TCP connection inside the tunnel").Base(err)
		}
		defer conn.Close()

		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
		}
	} else {
		conn, err := tunnel.DialUDPAddrPort(netip.AddrPort{}, addrPort)
		if err != nil {
			return newError("failed to open a UDP connection inside the tunnel").Base(err)
		}
		defer conn.Close()

		ipToDomain := new(sync.Map)
		requestFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.DownlinkOnly)
			return buf.Copy(link.Reader, newPacketWriter(conn, o, originalDestination, destination, ipToDomain), buf.UpdateActivity(timer))
		}
		responseFunc = func() error {
			defer timer.SetTimeout(p.Timeouts.UplinkOnly)
			return buf.Copy(newPacketReader(conn, ipToDomain), link.Writer, buf.UpdateActivity(timer))
		}
	}

	responseDonePost := task.OnSuccess(responseFunc, task.Close(link.Writer))
	if err := task.Run(ctx, requestFunc, responseDonePost); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return newError("connection ends").Base(err)
	}
	return nil
}

func toNetIPAddr(address net.Address) netip.Addr {
	addr, ok := netip.AddrFromSlice(address.IP())
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}
