//go:build unix

package masque

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	gonet "net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	connectip "github.com/miron404/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/yosida95/uritemplate/v3"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/transport/internet"
)

// TestProbeEndpoint asks a real WARP endpoint what it negotiates, which decides
// how often an idle tunnel wakes the radio: quic-go pings at
// min(KeepAlivePeriod, idle timeout / 2), where the idle timeout is the smaller
// of ours and the endpoint's. It needs outbound UDP and an enrolled device, so
// it only runs when MASQUE_PROBE_CONFIG names a usque config.json; the MASQUE
// probe workflow registers a throwaway device for it.
//
// MASQUE_PROBE_IDLE, in seconds, also holds a session open with keepalives off
// for up to that long, and reports when and how it ended.
func TestProbeEndpoint(t *testing.T) {
	path := os.Getenv("MASQUE_PROBE_CONFIG")
	if path == "" {
		t.Skip("set MASQUE_PROBE_CONFIG to a usque config.json")
	}
	o := probeOutbound(t, path)

	params, conn := probeDial(t, o, o.quicConfig())
	probeReport("advertised by the endpoint",
		"max_idle_timeout=%v max_udp_payload_size=%d max_datagram_frame_size=%d disable_active_migration=%v",
		params.MaxIdleTimeout, params.MaxUDPPayloadSize, params.MaxDatagramFrameSize, params.DisableActiveMigration)
	idle := o.quicConfig().MaxIdleTimeout
	if params.MaxIdleTimeout > 0 {
		idle = min(idle, params.MaxIdleTimeout)
	}
	probeReport("idle ping interval",
		"with a keepalive period of %v the tunnel pings every %v (negotiated idle timeout %v)",
		o.keepalivePeriod, min(o.keepalivePeriod, idle/2), idle)
	_ = conn.CloseWithError(0, "")

	wait, _ := strconv.Atoi(os.Getenv("MASQUE_PROBE_IDLE"))
	if wait <= 0 {
		return
	}
	// Nothing is sent from here on, so the session lasts exactly as long as
	// the side with the shorter idle timeout allows.
	quiet := &quic.Config{EnableDatagrams: true, MaxIdleTimeout: time.Duration(wait) * time.Second}
	_, conn = probeDial(t, o, quiet)
	start := time.Now()
	select {
	case <-conn.Context().Done():
		probeReport("idle session",
			"with keepalives off it lasted %v: %v",
			time.Since(start).Round(time.Second), context.Cause(conn.Context()))
	case <-time.After(time.Duration(wait)*time.Second + 30*time.Second):
		probeReport("idle session", "with keepalives off it was still open after %ds", wait)
	}
}

func probeReport(title, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	// An annotation, so the result can be read without the job's log.
	fmt.Printf("::notice title=%s::%s\n", title, message)
}

func probeOutbound(t *testing.T, path string) *Outbound {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		PrivateKey     string `json:"private_key"`
		EndpointV4     string `json:"endpoint_v4"`
		EndpointPubKey string `json:"endpoint_pub_key"`
		IPv4           string `json:"ipv4"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	privateKey, err := parsePrivateKey(config.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	endpointPublicKey, err := parseEndpointPublicKey(config.EndpointPubKey)
	if err != nil {
		t.Fatal(err)
	}
	return &Outbound{
		serverAddress:     net.ParseAddress(config.EndpointV4),
		serverPort:        443,
		serverName:        DefaultServerName,
		mtu:               defaultMTU,
		keepalivePeriod:   defaultKeepalivePeriod,
		privateKey:        privateKey,
		endpointPublicKey: endpointPublicKey,
		localAddresses:    []netip.Addr{netip.MustParseAddr(config.IPv4)},
	}
}

// probeDial sets a session up the way dialHTTP3 does, CONNECT-IP request
// included, recording the transport parameters the endpoint sends.
func probeDial(t *testing.T, outbound *Outbound, config *quic.Config) (qlog.ParametersSet, *quic.Conn) {
	tlsConfig, err := outbound.prepareTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	recorder := &parametersRecorder{received: make(chan qlog.ParametersSet, 1)}
	config.Tracer = func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return recorder }

	socket, err := gonet.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	transport := &quic.Transport{Conn: socket, ConnectionIDLength: 20}
	t.Cleanup(func() { _ = transport.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	endpoint := &gonet.UDPAddr{IP: outbound.serverAddress.IP(), Port: int(outbound.serverPort)}
	conn, err := transport.Dial(ctx, endpoint, tlsConfig, config)
	if err != nil {
		t.Fatal("QUIC handshake failed: ", err)
	}
	h3 := &http3.Transport{EnableDatagrams: true, AdditionalSettings: map[uint64]uint64{0x276: 1}, DisableCompression: true}
	ipConn, response, err := connectip.Dial(ctx, h3.NewClientConn(conn), uritemplate.MustNew(connectURI),
		requestProtocol, http.Header{"User-Agent": []string{""}}, true)
	if err != nil {
		t.Fatal("CONNECT-IP failed: ", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatal("CONNECT-IP refused: ", response.Status)
	}
	t.Cleanup(func() { _ = ipConn.Close() })

	select {
	case params := <-recorder.received:
		return params, conn
	default:
		t.Fatal("the endpoint's transport parameters were not recorded")
	}
	return qlog.ParametersSet{}, nil
}

// parametersRecorder keeps the transport parameters the peer sends and
// ignores every other event.
type parametersRecorder struct {
	once     sync.Once
	received chan qlog.ParametersSet
}

func (r *parametersRecorder) AddProducer() qlogwriter.Recorder { return r }
func (r *parametersRecorder) SupportsSchemas(schema string) bool {
	return schema == qlog.EventSchema
}
func (r *parametersRecorder) Close() error { return nil }
func (r *parametersRecorder) RecordEvent(event qlogwriter.Event) {
	if params, ok := event.(qlog.ParametersSet); ok && params.Initiator == qlog.InitiatorRemote && !params.Restore {
		r.once.Do(func() { r.received <- params })
	}
}

// TestProbeThroughput moves data through a real tunnel, in each mode, and
// reports the speed and the CPU this process spent per gigabyte, which is the
// cost a phone pays in battery for the same traffic. The far end is
// speed.cloudflare.com, reached inside the tunnel over TLS like any app would.
// Needs MASQUE_PROBE_CONFIG as above; MASQUE_PROBE_SPEED is the megabytes
// moved each way.
func TestProbeThroughput(t *testing.T) {
	path := os.Getenv("MASQUE_PROBE_CONFIG")
	megabytes, _ := strconv.Atoi(os.Getenv("MASQUE_PROBE_SPEED"))
	if path == "" || megabytes <= 0 {
		t.Skip("set MASQUE_PROBE_CONFIG and MASQUE_PROBE_SPEED")
	}
	size := int64(megabytes) << 20
	label := os.Getenv("MASQUE_PROBE_LABEL")
	addresses, err := gonet.DefaultResolver.LookupNetIP(context.Background(), "ip4", speedHost)
	if err != nil || len(addresses) == 0 {
		t.Fatal("cannot resolve ", speedHost, ": ", err)
	}
	target := netip.AddrPortFrom(addresses[0], 443)

	for _, mode := range []string{"quic", "h2"} {
		o := probeOutbound(t, path)
		var dialer internet.Dialer = probeDialer{}
		if mode == "h2" {
			o.useHTTP2 = true
			o.http2Address = net.ParseAddress(probeH2Address(t, path))
		}
		tun, err := newTunnel(context.Background(), o, dialer)
		if err != nil {
			t.Fatal(err)
		}
		// One small request first, so the session is up before measuring.
		if err := speedTransfer(tun, target, "GET", 1<<10); err != nil {
			t.Fatal(mode, ": ", err)
		}
		for _, method := range []string{"GET", "POST"} {
			for range 2 {
				var before, after syscall.Rusage
				_ = syscall.Getrusage(syscall.RUSAGE_SELF, &before)
				start := time.Now()
				if err := speedTransfer(tun, target, method, size); err != nil {
					t.Fatal(mode, " ", method, ": ", err)
				}
				elapsed := time.Since(start)
				_ = syscall.Getrusage(syscall.RUSAGE_SELF, &after)
				cpu := time.Duration(after.Utime.Nano() - before.Utime.Nano() + after.Stime.Nano() - before.Stime.Nano())
				direction := map[string]string{"GET": "download", "POST": "upload"}[method]
				probeReport(fmt.Sprintf("%s %s %s", label, mode, direction),
					"%.0f Mbit/s, %.1f s of CPU per GB", float64(size)*8/elapsed.Seconds()/1e6,
					cpu.Seconds()/(float64(size)/1e9))
			}
		}
		_ = tun.Close()
	}
}

const speedHost = "speed.cloudflare.com"

// speedTransfer downloads or uploads size bytes over HTTPS inside the tunnel.
func speedTransfer(tun *tunnel, target netip.AddrPort, method string, size int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, err := tun.DialContextTCPAddrPort(ctx, target)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	tlsConn := tls.Client(conn, &tls.Config{ServerName: speedHost})
	var request *http.Request
	if method == "GET" {
		request, _ = http.NewRequest("GET", fmt.Sprintf("https://%s/__down?bytes=%d", speedHost, size), nil)
	} else {
		request, _ = http.NewRequest("POST", "https://"+speedHost+"/__up", io.LimitReader(zeroReader{}, size))
		request.ContentLength = size
	}
	request.Close = true
	if err := request.Write(tlsConn); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReaderSize(tlsConn, 64<<10), request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	n, err := io.Copy(io.Discard, response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", speedHost, response.Status)
	}
	if method == "GET" && n != size {
		return fmt.Errorf("downloaded %d bytes of %d", n, size)
	}
	return nil
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func probeH2Address(t *testing.T, path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		EndpointH2V4 string `json:"endpoint_h2_v4"`
	}
	_ = json.Unmarshal(data, &config)
	if config.EndpointH2V4 == "" {
		return "162.159.198.2"
	}
	return config.EndpointH2V4
}

// probeDialer dials the way the core does on a device: a UDP socket of its
// own for QUIC, so path MTU discovery works, and a plain TCP connection for
// HTTP/2.
type probeDialer struct{}

func (probeDialer) Dial(ctx context.Context, destination net.Destination) (internet.Connection, error) {
	if destination.Network == net.Network_UDP {
		socket, err := gonet.ListenUDP("udp", nil)
		if err != nil {
			return nil, err
		}
		return &internet.PacketConnWrapper{Conn: socket, Dest: &gonet.UDPAddr{
			IP:   destination.Address.IP(),
			Port: int(destination.Port),
		}}, nil
	}
	var d gonet.Dialer
	return d.DialContext(ctx, "tcp", destination.NetAddr())
}

func (probeDialer) Address() net.Address { return nil }
