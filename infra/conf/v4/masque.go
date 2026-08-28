package v4

import (
	"strings"

	"github.com/golang/protobuf/proto"

	"github.com/exclavenetwork/exclave-core/v5/infra/conf/cfgcommon"
	"github.com/exclavenetwork/exclave-core/v5/proxy/masque"
)

type MasqueClientConfig struct {
	Address           *cfgcommon.Address `json:"address"`
	Port              uint16             `json:"port"`
	HTTP2Address      *cfgcommon.Address `json:"http2Address"`
	PrivateKey        string             `json:"privateKey"`
	EndpointPublicKey string             `json:"endpointPublicKey"`
	LocalAddress      []string           `json:"localAddress"`
	ServerName        string             `json:"serverName"`
	MTU               int32              `json:"mtu"`
	UseHTTP2          bool               `json:"useHTTP2"`
	AllowInsecure     bool               `json:"allowInsecure"`
	KeepalivePeriod   uint32             `json:"keepalivePeriod"`
	InitialPacketSize uint32             `json:"initialPacketSize"`
	DomainStrategy    string             `json:"domainStrategy"`
}

func (c *MasqueClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, newError("missing server address")
	}
	if c.PrivateKey == "" {
		return nil, newError("missing private key")
	}
	if !c.AllowInsecure && c.EndpointPublicKey == "" {
		return nil, newError("missing endpoint public key")
	}
	if len(c.LocalAddress) == 0 {
		return nil, newError("missing local address")
	}
	if c.InitialPacketSize > 65535 {
		return nil, newError("invalid initial packet size: ", c.InitialPacketSize)
	}
	config := &masque.ClientConfig{
		Address:           c.Address.Build(),
		Port:              uint32(c.Port),
		PrivateKey:        c.PrivateKey,
		EndpointPublicKey: c.EndpointPublicKey,
		LocalAddress:      c.LocalAddress,
		ServerName:        c.ServerName,
		Mtu:               c.MTU,
		UseHttp2:          c.UseHTTP2,
		AllowInsecure:     c.AllowInsecure,
		KeepalivePeriod:   c.KeepalivePeriod,
		InitialPacketSize: c.InitialPacketSize,
	}
	if c.HTTP2Address != nil {
		config.Http2Address = c.HTTP2Address.Build()
	}
	switch strings.ToLower(c.DomainStrategy) {
	case "useip", "":
		config.DomainStrategy = masque.ClientConfig_USE_IP
	case "useipv4":
		config.DomainStrategy = masque.ClientConfig_USE_IP4
	case "useipv6":
		config.DomainStrategy = masque.ClientConfig_USE_IP6
	case "preferipv4":
		config.DomainStrategy = masque.ClientConfig_PREFER_IP4
	case "preferipv6":
		config.DomainStrategy = masque.ClientConfig_PREFER_IP6
	default:
		return nil, newError("unsupported domain strategy: ", c.DomainStrategy)
	}
	return config, nil
}
