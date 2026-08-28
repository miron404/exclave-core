package v4_test

import (
	"testing"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/infra/conf/cfgcommon"
	"github.com/exclavenetwork/exclave-core/v5/infra/conf/cfgcommon/testassist"
	v4 "github.com/exclavenetwork/exclave-core/v5/infra/conf/v4"
	"github.com/exclavenetwork/exclave-core/v5/proxy/masque"
)

func TestMasqueOutboundConfig(t *testing.T) {
	creator := func() cfgcommon.Buildable {
		return new(v4.MasqueClientConfig)
	}

	testassist.RunMultiTestCase(t, []testassist.TestCase{
		{
			Input: `{
				"address": "162.159.198.1",
				"port": 443,
				"http2Address": "162.159.198.2",
				"privateKey": "cHJpdmF0ZQ==",
				"endpointPublicKey": "-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n",
				"localAddress": ["172.16.0.2", "2606:4700:110::1"],
				"serverName": "consumer-masque.cloudflareclient.com",
				"mtu": 1280,
				"useHTTP2": true,
				"keepalivePeriod": 30,
				"initialPacketSize": 1242,
				"domainStrategy": "preferIPv4"
			}`,
			Parser: testassist.LoadJSON(creator),
			Output: &masque.ClientConfig{
				Address:           net.NewIPOrDomain(net.ParseAddress("162.159.198.1")),
				Port:              443,
				Http2Address:      net.NewIPOrDomain(net.ParseAddress("162.159.198.2")),
				PrivateKey:        "cHJpdmF0ZQ==",
				EndpointPublicKey: "-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n",
				LocalAddress:      []string{"172.16.0.2", "2606:4700:110::1"},
				ServerName:        "consumer-masque.cloudflareclient.com",
				Mtu:               1280,
				UseHttp2:          true,
				KeepalivePeriod:   30,
				InitialPacketSize: 1242,
				DomainStrategy:    masque.ClientConfig_PREFER_IP4,
			},
		},
		{
			// Only the material that cannot be defaulted is mandatory.
			Input: `{
				"address": "162.159.198.1",
				"port": 443,
				"privateKey": "cHJpdmF0ZQ==",
				"endpointPublicKey": "key",
				"localAddress": ["172.16.0.2"]
			}`,
			Parser: testassist.LoadJSON(creator),
			Output: &masque.ClientConfig{
				Address:           net.NewIPOrDomain(net.ParseAddress("162.159.198.1")),
				Port:              443,
				PrivateKey:        "cHJpdmF0ZQ==",
				EndpointPublicKey: "key",
				LocalAddress:      []string{"172.16.0.2"},
				DomainStrategy:    masque.ClientConfig_USE_IP,
			},
		},
	})
}

func TestMasqueOutboundConfigRejectsIncompleteInput(t *testing.T) {
	for name, input := range map[string]string{
		"no address":          `{"privateKey": "a", "endpointPublicKey": "b", "localAddress": ["172.16.0.2"]}`,
		"no private key":      `{"address": "162.159.198.1", "endpointPublicKey": "b", "localAddress": ["172.16.0.2"]}`,
		"no endpoint key":     `{"address": "162.159.198.1", "privateKey": "a", "localAddress": ["172.16.0.2"]}`,
		"no local address":    `{"address": "162.159.198.1", "privateKey": "a", "endpointPublicKey": "b"}`,
		"bad domain strategy": `{"address": "162.159.198.1", "privateKey": "a", "endpointPublicKey": "b", "localAddress": ["172.16.0.2"], "domainStrategy": "nonsense"}`,
		"huge initial packet": `{"address": "162.159.198.1", "privateKey": "a", "endpointPublicKey": "b", "localAddress": ["172.16.0.2"], "initialPacketSize": 70000}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := testassist.LoadJSON(func() cfgcommon.Buildable {
				return new(v4.MasqueClientConfig)
			})(input); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestMasqueOutboundConfigAllowsInsecureWithoutEndpointKey(t *testing.T) {
	input := `{"address": "162.159.198.1", "privateKey": "a", "localAddress": ["172.16.0.2"], "allowInsecure": true}`
	if _, err := testassist.LoadJSON(func() cfgcommon.Buildable {
		return new(v4.MasqueClientConfig)
	})(input); err != nil {
		t.Error(err)
	}
}
