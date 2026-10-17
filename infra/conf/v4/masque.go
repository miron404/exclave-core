package v4

import (
	"strings"

	"github.com/golang/protobuf/proto"

	"github.com/exclavenetwork/exclave-core/v5/infra/conf/cfgcommon"
	"github.com/exclavenetwork/exclave-core/v5/proxy/masque"
)

type MASQUEClientConfig struct {
	Address        *cfgcommon.Address `json:"address"`
	Port           uint16             `json:"port"`
	Username       *string            `json:"username"`
	Password       *string            `json:"password"`
	Headers        map[string]string  `json:"headers"`
	URITemplate    string             `json:"uriTemplate"`
	Version        int32              `json:"version"`
	MTU            int32              `json:"mtu"`
	DomainStrategy string             `json:"domainStrategy"`
}

func (c *MASQUEClientConfig) Build() (proto.Message, error) {
	if c.Address == nil {
		return nil, newError("address is not set")
	}
	config := &masque.ClientConfig{
		Address:     c.Address.Build(),
		Port:        uint32(c.Port),
		Username:    c.Username,
		Password:    c.Password,
		Headers:     c.Headers,
		UriTemplate: c.URITemplate,
		Version:     c.Version,
		Mtu:         c.MTU,
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
