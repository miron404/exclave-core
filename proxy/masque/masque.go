// Package masque implements a MASQUE (CONNECT-IP, RFC 9484) outbound, as
// deployed by Cloudflare WARP.
//
// The tunnel setup follows https://github.com/Diniboy1123/usque (MIT), which
// documented Cloudflare's non standard bits: the client authenticates with a
// short lived self signed certificate carrying the enrolled device key, the
// endpoint certificate is pinned by public key rather than by name, and the
// CONNECT-IP request is sent with the `cf-connect-ip` protocol.
package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	gonet "net"
	"net/http"
	"strings"
	"time"

	connectip "github.com/miron404/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

const (
	// DefaultServerName is the SNI the official client sends. It never matches
	// the endpoint certificate, which is why the key is pinned instead.
	DefaultServerName = "consumer-masque.cloudflareclient.com"
	// connectURI is the CONNECT-IP request target.
	connectURI = "https://cloudflareaccess.com"
	// requestProtocol is Cloudflare's non standard CONNECT-IP protocol name.
	requestProtocol = "cf-connect-ip"

	defaultMTU             = 1280
	defaultKeepalivePeriod = 30 * time.Second
	// defaultIdleTimeout is quic-go's own default, kept as the floor for the
	// idle timeout the keepalive period is turned into, so that a short period
	// does not also shorten how long a stalled connection is given to recover.
	defaultIdleTimeout = 30 * time.Second
	// clientCertValidity matches the official client; the certificate only
	// carries the enrolled key, so a short lifetime costs nothing.
	clientCertValidity = 24 * time.Hour

	// migrationProbeTimeout bounds how long a new path is probed before the
	// session is given up and redialed instead. Probes back off exponentially
	// from 200ms, so this is a handful of packets at most.
	migrationProbeTimeout = 5 * time.Second
	// maxMigrations bounds the sockets one session collects. quic-go keeps
	// listening on every transport a connection has used, and closing one
	// closes the connection, so each move holds a socket until the session
	// ends. Past this, a network change redials instead, which releases them.
	maxMigrations = 4
)

// accessDeniedHint explains the endpoint rejecting the enrolled key.
const accessDeniedHint = "login failed: the TLS key and certificate are not enrolled with the endpoint"

func parsePrivateKey(encoded string) (*ecdsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, newError("failed to decode private key").Base(err)
	}
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, newError("failed to parse private key").Base(err)
	}
	return key, nil
}

func parseEndpointPublicKey(encoded string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		return nil, newError("failed to decode endpoint public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, newError("failed to parse endpoint public key").Base(err)
	}
	publicKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, newError("endpoint public key is not ECDSA")
	}
	return publicKey, nil
}

// generateClientCert builds the self signed certificate presented to the
// endpoint. Only the embedded public key is checked by the peer.
func generateClientCert(privateKey *ecdsa.PrivateKey) ([][]byte, error) {
	certificate, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(clientCertValidity),
	}, &x509.Certificate{}, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, newError("failed to generate client certificate").Base(err)
	}
	return [][]byte{certificate}, nil
}

// prepareTLSConfig builds a TLS configuration pinned to the endpoint key.
//
// The SNI is a Cloudflare hostname that the endpoint certificate does not
// cover, so name verification has to be off; the endpoint is authenticated by
// comparing its public key with the one handed out at enrollment instead.
func (o *Outbound) prepareTLSConfig() (*tls.Config, error) {
	certificate, err := generateClientCert(o.privateKey)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{{Certificate: certificate, PrivateKey: o.privateKey}},
		ServerName:         o.serverName,
		NextProtos:         []string{http3.NextProtoH3},
		InsecureSkipVerify: true,
	}
	if o.endpointPublicKey == nil {
		return tlsConfig, nil
	}
	tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return nil
		}
		certificate, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return x509.ErrUnsupportedAlgorithm
		}
		if !publicKey.Equal(o.endpointPublicKey) {
			// 10 is x509.NoValidChains, spelled out to keep the older Go
			// versions this core still supports building.
			return x509.CertificateInvalidError{
				Cert:   certificate,
				Reason: 10,
				Detail: "endpoint public key does not match the enrolled one",
			}
		}
		return nil
	}
	return tlsConfig, nil
}

// quicConfig builds the QUIC configuration the tunnel is dialed with.
//
// The idle timeout has to be set alongside the keepalive period. quic-go pings
// at min(KeepAlivePeriod, MaxIdleTimeout/2), so leaving the idle timeout at its
// 30s default silently halves every configured period: the 30s default here
// became a ping every 15 seconds, which is a radio wakeup every 15 seconds for
// as long as the tunnel is up. Two keepalive periods leave the connection
// exactly one unanswered ping of grace, which is the arrangement that clamp
// exists to produce.
//
// The peer's own advertised idle timeout is still taken into account, and it is
// the smaller of the two that counts, so the period asked for here is a ceiling
// rather than a promise.
func (o *Outbound) quicConfig() *quic.Config {
	config := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: o.keepalivePeriod,
		MaxIdleTimeout:  max(2*o.keepalivePeriod, defaultIdleTimeout),
	}
	if o.initialPacketSize > 0 {
		config.InitialPacketSize = o.initialPacketSize
		config.DisablePathMTUDiscovery = true
	}
	return config
}

// ipSession is one live CONNECT-IP tunnel together with everything that has to be
// torn down with it.
type ipSession struct {
	// canDiscoverPathMTU reports whether the connection can grow its packets
	// beyond the initial size. When it cannot, a packet that does not fit will
	// never fit, and the tunnel has to be resized instead of waiting.
	canDiscoverPathMTU bool
	// counters are the core's byte counters for this connection, fed by the
	// tunnel because the socket itself is handed to quic-go unwrapped.
	counters *socketCounters
	// cancel releases the context the session was dialed with. The HTTP/2
	// transport keeps the request alive for the lifetime of the tunnel, so this
	// must not be called before the session is torn down.
	cancel        context.CancelFunc
	ipConn        *connectip.Conn
	transport     *http3.Transport
	h2Transport   *http2.Transport
	quicConn      *quic.Conn
	quicTransport *quic.Transport
	packetConn    gonet.PacketConn
	// migrations are the paths the connection was moved onto, in order.
	migrations []migratedPath
}

// migratedPath is a socket a QUIC connection was moved onto, and the transport
// reading it.
type migratedPath struct {
	transport  *quic.Transport
	packetConn gonet.PacketConn
}

func (s *ipSession) Close() {
	if s == nil {
		return
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.ipConn != nil {
		_ = s.ipConn.Close()
	}
	if s.transport != nil {
		_ = s.transport.Close()
	}
	if s.h2Transport != nil {
		// The tunnel owns its transport, so dropping the pooled TCP connection
		// here keeps a reconnect from leaking the previous one.
		s.h2Transport.CloseIdleConnections()
	}
	if s.quicConn != nil {
		_ = s.quicConn.CloseWithError(0, "")
	}
	if s.quicTransport != nil {
		_ = s.quicTransport.Close()
	}
	if s.packetConn != nil {
		_ = s.packetConn.Close()
	}
	for _, path := range s.migrations {
		_ = path.transport.Close()
		_ = path.packetConn.Close()
	}
}

// migrate moves a QUIC session onto a socket opened on the current network.
// The connection is kept, and with it the CONNECT-IP session, the addresses in
// the tunnel and every flow running over them.
//
// It costs no handshake: the new path is validated with PATH_CHALLENGE frames
// and the connection switches to it once the endpoint answers. quic-go then
// resets the congestion controller and restarts path MTU discovery from the
// initial packet size, since nothing learned about the old path holds on the
// new one.
//
// On failure the connection may already be unusable, since the socket is
// registered with it, so the caller is expected to redial.
func (o *Outbound) migrate(ctx context.Context, dialer internet.Dialer, sess *ipSession) error {
	if sess.quicConn == nil {
		return newError("an HTTP/2 connection cannot move to another network")
	}
	if !sess.canDiscoverPathMTU {
		// The socket belongs to another outbound, which follows network
		// changes on its own.
		return newError("the connection runs through another outbound")
	}
	if len(sess.migrations) >= maxMigrations {
		return newError("the connection has already moved ", len(sess.migrations), " times")
	}
	ctx, cancel := context.WithTimeout(ctx, migrationProbeTimeout)
	defer cancel()

	endpoint := sess.quicConn.RemoteAddr()
	packetConn, _, isSocket, err := listenPacket(ctx, dialer, o.endpoint(net.Network_UDP), endpoint)
	if err != nil {
		return newError("failed to open a socket on the new network").Base(err)
	}
	if !isSocket {
		_ = packetConn.Close()
		return newError("the new network did not give a socket")
	}
	transport := &quic.Transport{Conn: packetConn, ConnectionIDLength: 20}
	// Owned by the session from here on: once the connection is registered on
	// the transport, closing it would close the connection.
	sess.migrations = append(sess.migrations, migratedPath{transport: transport, packetConn: packetConn})

	path, err := sess.quicConn.AddPath(transport)
	if err != nil {
		return newError("failed to add a path").Base(err)
	}
	if err := path.Probe(ctx); err != nil {
		return newError("the endpoint did not answer on the new path").Base(err)
	}
	if err := path.Switch(); err != nil {
		return newError("failed to switch to the new path").Base(err)
	}
	newError("QUIC connection moved to ", packetConn.LocalAddr()).AtInfo().WriteToLog()
	return nil
}

// dial establishes a CONNECT-IP session over the configured transport.
func (o *Outbound) dial(ctx context.Context, dialer internet.Dialer) (*ipSession, error) {
	tlsConfig, err := o.prepareTLSConfig()
	if err != nil {
		return nil, err
	}
	var sess *ipSession
	var response *http.Response
	if o.useHTTP2 {
		newError("dialing MASQUE endpoint ", o.endpoint(net.Network_TCP).NetAddr(), " over HTTP/2").AtInfo().WriteToLog()
		sess, response, err = o.dialHTTP2(ctx, dialer, tlsConfig)
	} else {
		newError("dialing MASQUE endpoint ", o.endpoint(net.Network_UDP).NetAddr(), " over QUIC").AtInfo().WriteToLog()
		sess, response, err = o.dialHTTP3(ctx, dialer, tlsConfig)
	}
	if err != nil {
		if strings.Contains(err.Error(), "tls: access denied") {
			return nil, newError(accessDeniedHint).Base(err)
		}
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		sess.Close()
		return nil, newError("endpoint rejected the tunnel: ", response.Status)
	}
	return sess, nil
}

// dialHTTP3 opens the tunnel over QUIC. The UDP socket comes from the core
// dialer, so on Android it is protected from the VPN service and honours the
// outbound's sockopt settings.
func (o *Outbound) dialHTTP3(ctx context.Context, dialer internet.Dialer, tlsConfig *tls.Config) (*ipSession, *http.Response, error) {
	destination := o.endpoint(net.Network_UDP)
	if !destination.Address.Family().IsIP() {
		return nil, nil, newError("QUIC mode needs an IP endpoint, got ", destination.Address)
	}
	endpoint := &gonet.UDPAddr{
		IP:   destination.Address.IP(),
		Port: int(destination.Port),
	}
	packetConn, counters, canDiscoverPathMTU, err := listenPacket(ctx, dialer, destination, endpoint)
	if err != nil {
		return nil, nil, newError("failed to listen packet").Base(err)
	}
	newError("QUIC socket bound to ", packetConn.LocalAddr(),
		", path MTU discovery: ", canDiscoverPathMTU).AtInfo().WriteToLog()
	// Without an explicit connection ID length the endpoint occasionally
	// answers with PROTOCOL_VIOLATION and drops the connection.
	transport := &quic.Transport{Conn: packetConn, ConnectionIDLength: 20}
	quicConn, err := transport.Dial(ctx, endpoint, tlsConfig, o.quicConfig())
	if err != nil {
		_ = transport.Close()
		_ = packetConn.Close()
		return nil, nil, newError("failed to dial QUIC").Base(err)
	}
	newError("QUIC handshake completed, requesting CONNECT-IP").AtInfo().WriteToLog()
	h3Transport := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			// SETTINGS_H3_DATAGRAM_00, deprecated but still sent by the
			// official client and expected by the endpoint.
			0x276: 1,
		},
		DisableCompression: true,
	}
	ipConn, response, err := connectip.Dial(
		ctx,
		h3Transport.NewClientConn(quicConn),
		uritemplate.MustNew(connectURI),
		requestProtocol,
		http.Header{"User-Agent": []string{""}},
		true,
	)
	if err != nil {
		_ = h3Transport.Close()
		_ = quicConn.CloseWithError(0, "connect-ip dial failed")
		_ = transport.Close()
		_ = packetConn.Close()
		return nil, nil, newError("failed to dial connect-ip").Base(err)
	}
	return &ipSession{
		canDiscoverPathMTU: canDiscoverPathMTU,
		counters:           counters,
		ipConn:             ipConn,
		transport:          h3Transport,
		quicConn:           quicConn,
		quicTransport:      transport,
		packetConn:         packetConn,
	}, response, nil
}

// dialHTTP2 opens the tunnel over TCP+TLS/HTTP2, the fallback for networks that
// block QUIC.
func (o *Outbound) dialHTTP2(ctx context.Context, dialer internet.Dialer, tlsConfig *tls.Config) (*ipSession, *http.Response, error) {
	transport := o.http2Transport(dialer, tlsConfig)
	client := &http.Client{Transport: transport}
	ipConn, response, err := connectip.DialH2(ctx, client, uritemplate.MustNew(connectURI), http.Header{
		"User-Agent":       []string{""},
		"cf-connect-proto": []string{requestProtocol},
		// TODO: post quantum key agreement is not implemented yet.
		"pq-enabled": []string{"false"},
	})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, newError("failed to dial connect-ip over HTTP/2").Base(err)
	}
	return &ipSession{ipConn: ipConn, h2Transport: transport}, response, nil
}

// http2Transport builds the transport the CONNECT-IP request runs on. It dials
// the endpoint itself, so that the connection the tunnel lives on is the one
// this outbound made rather than one the pool happens to hold.
func (o *Outbound) http2Transport(dialer internet.Dialer, tlsConfig *tls.Config) *http2.Transport {
	destination := o.endpoint(net.Network_TCP)
	h2TLSConfig := tlsConfig.Clone()
	h2TLSConfig.NextProtos = []string{"h2"}
	return &http2.Transport{
		DisableCompression: true,
		// A silent TCP path is indistinguishable from an idle one: the tunnel
		// request stays open, both pumps stay parked, and nothing fails, so the
		// supervisor never learns to redial. A ping settles it, at the cost of
		// a wakeup per period, which is why it is off unless asked for.
		ReadIdleTimeout: o.http2PingPeriod,
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (gonet.Conn, error) {
			conn, err := dialer.Dial(ctx, destination)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, h2TLSConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
}

// endpointPacketConn presents a stream shaped connection as the net.PacketConn
// quic-go expects. Every datagram is sent to, and reported as coming from, the
// single endpoint the tunnel dialed.
type endpointPacketConn struct {
	gonet.Conn
	endpoint gonet.Addr
}

func (c *endpointPacketConn) ReadFrom(p []byte) (int, gonet.Addr, error) {
	n, err := c.Read(p)
	return n, c.endpoint, err
}

func (c *endpointPacketConn) WriteTo(p []byte, _ gonet.Addr) (int, error) {
	return c.Write(p)
}
