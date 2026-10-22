// Package speedtest measures how fast a download runs through an instance.
//
// The app binds this package next to libexclavecore, which keeps the dialer
// of its instance to itself. So the download reaches the instance through
// the unix socket of an ipc inbound added to the instance for the test, and
// takes the same route as anything the instance carries: through the whole
// chain, front and landing proxies included.
package speedtest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	gonet "net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/common/protocol"
)

// The header of a stream into an ipc inbound, as proxy/ipc reads it.
const commandTCP byte = 1

var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(0x01, net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(0x04, net.AddressFamilyIPv6),
	protocol.AddressFamilyByte(0x03, net.AddressFamilyDomain),
)

const (
	maxConnections   = 16
	progressInterval = 500 * time.Millisecond
	readSize         = 64 << 10
)

var (
	errConnectTimeout = errors.New("no response within the connect timeout")
	errCanceled       = errors.New("canceled")
	errNoData         = errors.New("no data received")
)

// Listener hears how a running test is doing.
type Listener interface {
	// OnProgress is called about twice a second once data flows, with the
	// bytes received so far and the time since the first of them arrived.
	OnProgress(bytes int64, elapsedMillis int64)
}

// Result is what a finished test measured.
type Result struct {
	// Bytes is how much of the response bodies arrived.
	Bytes int64
	// ElapsedMillis runs from the first byte of a body to the end of the
	// test. Connecting is left out, so a slow handshake through a long chain
	// does not read as a slow server: ConnectMillis has it instead.
	ElapsedMillis int64
	// ConnectMillis is the time the fastest connection took from dialing to
	// its response headers.
	ConnectMillis int64
}

// Test is one speed test. Cancel stops it from another thread.
type Test struct {
	socketPath string
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewTest makes a test that downloads through the ipc inbound listening on
// socketPath.
func NewTest(socketPath string) *Test {
	ctx, cancel := context.WithCancel(context.Background())
	return &Test{socketPath: socketPath, ctx: ctx, cancel: cancel}
}

// Cancel stops a running test, which then fails with errCanceled.
func (t *Test) Cancel() {
	t.cancel()
}

// Run downloads link over parallel connections until maxBytes have arrived
// in all, durationMillis have passed since the first byte, or every response
// has ended. Each connection has connectTimeoutMillis to get its response
// headers. A test that got some data before it ended still has a result,
// whatever stopped it.
func (t *Test) Run(link string, maxBytes int64, connections int32, connectTimeoutMillis int32, durationMillis int32, listener Listener) (*Result, error) {
	request, err := http.NewRequest(http.MethodGet, link, nil)
	if err != nil {
		return nil, err
	}
	if request.URL.Scheme != "http" && request.URL.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", request.URL.Scheme)
	}
	connections = min(max(connections, 1), maxConnections)
	connectTimeout := time.Duration(connectTimeoutMillis) * time.Millisecond
	duration := time.Duration(durationMillis) * time.Millisecond

	ctx, stop := context.WithCancel(t.ctx)
	defer stop()
	m := &meter{start: time.Now(), maxBytes: maxBytes, duration: duration, stop: stop}
	// The window opens at the first byte, so a response whose headers came
	// but whose body never does would otherwise hold the test forever.
	deadline := time.AfterFunc(connectTimeout+duration, m.timeUp)
	defer deadline.Stop()

	done := make(chan struct{})
	if listener != nil {
		go m.report(listener, done)
	}
	var wg sync.WaitGroup
	connects := make([]time.Duration, connections)
	errs := make([]error, connections)
	for i := range connections {
		wg.Go(func() {
			connects[i], errs[i] = t.download(ctx, request, connectTimeout, m)
		})
	}
	wg.Wait()
	deadline.Stop()
	m.closeWindow()
	close(done)

	if t.ctx.Err() != nil {
		return nil, errCanceled
	}
	total := m.bytes.Load()
	if total == 0 {
		for _, err := range errs {
			if err != nil {
				return nil, err
			}
		}
		return nil, errNoData
	}
	result := &Result{
		Bytes:         total,
		ElapsedMillis: max(m.elapsed().Milliseconds(), 1),
	}
	for _, connect := range connects {
		if connect > 0 && (result.ConnectMillis == 0 || connect.Milliseconds() < result.ConnectMillis) {
			result.ConnectMillis = max(connect.Milliseconds(), 1)
		}
	}
	return result, nil
}

// download reads one response until it ends or the test stops, and returns
// how long the response took to start.
func (t *Test) download(ctx context.Context, template *http.Request, connectTimeout time.Duration, m *meter) (time.Duration, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	connectTimer := time.AfterFunc(connectTimeout, cancel)

	// A transport of its own for each, so that HTTP/2 does not fold the
	// connections into one.
	transport := &http.Transport{
		DialContext:        t.dial,
		ForceAttemptHTTP2:  true,
		DisableKeepAlives:  true,
		DisableCompression: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}

	began := time.Now()
	response, err := client.Do(template.Clone(ctx))
	if !connectTimer.Stop() {
		if err == nil {
			response.Body.Close()
		}
		if ctx.Err() != nil && m.stopped() {
			return 0, nil
		}
		return 0, errConnectTimeout
	}
	if err != nil {
		if m.stopped() {
			return 0, nil
		}
		return 0, err
	}
	defer response.Body.Close()
	connect := time.Since(began)
	if response.StatusCode != http.StatusOK {
		return connect, fmt.Errorf("HTTP %s", response.Status)
	}

	buffer := make([]byte, readSize)
	for {
		n, err := response.Body.Read(buffer)
		if n > 0 && !m.add(n) {
			return connect, nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) || m.stopped() {
				return connect, nil
			}
			return connect, err
		}
	}
}

func (t *Test) dial(ctx context.Context, network, address string) (gonet.Conn, error) {
	destination, err := net.ParseDestination(network + ":" + address)
	if err != nil {
		return nil, err
	}
	var header bytes.Buffer
	header.WriteByte(commandTCP)
	if err := addrParser.WriteAddressPort(&header, destination.Address, destination.Port); err != nil {
		return nil, err
	}
	var dialer gonet.Dialer
	conn, err := dialer.DialContext(ctx, "unix", t.socketPath)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(header.Bytes()); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// meter counts what arrives on all the connections of a test, and ends the
// test once it has enough. Times are kept as offsets from start, so that
// every connection can update them without a lock.
type meter struct {
	start    time.Time
	maxBytes int64
	duration time.Duration
	stop     context.CancelFunc

	// over is set once the test has enough, and what arrives later, still on
	// its way when it ended, is not counted.
	over      atomic.Bool
	bytes     atomic.Int64
	firstByte atomic.Int64
	lastByte  atomic.Int64
	// timeUpAt is set when the test ran out of time rather than data, and
	// the window then ends there: ending it at the last byte would leave out
	// the stall that ran the time out.
	timeUpAt  atomic.Int64
	firstOnce sync.Once
	window    *time.Timer
}

func (m *meter) now() int64 {
	return max(int64(time.Since(m.start)), 1)
}

// add counts n bytes that arrived, and tells whether the test wants more.
func (m *meter) add(n int) bool {
	if m.over.Load() {
		return false
	}
	now := m.now()
	m.firstOnce.Do(func() {
		m.firstByte.Store(now)
		m.window = time.AfterFunc(m.duration, m.timeUp)
	})
	m.lastByte.Store(now)
	if m.bytes.Add(int64(n)) >= m.maxBytes {
		m.end()
		return false
	}
	return true
}

func (m *meter) end() {
	m.over.Store(true)
	m.stop()
}

// closeWindow is called once every download is over, so that the window of
// responses that all ended early does not end again later on its timer.
func (m *meter) closeWindow() {
	if m.window != nil {
		m.window.Stop()
	}
}

func (m *meter) timeUp() {
	m.timeUpAt.CompareAndSwap(0, m.now())
	m.end()
}

// stopped tells an error the test caused by ending from a failure.
func (m *meter) stopped() bool {
	return m.over.Load()
}

func (m *meter) elapsed() time.Duration {
	end := m.timeUpAt.Load()
	if end == 0 {
		end = m.lastByte.Load()
	}
	return time.Duration(end - m.firstByte.Load())
}

func (m *meter) report(listener Listener, done <-chan struct{}) {
	ticker := time.NewTicker(progressInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			first := m.firstByte.Load()
			if first == 0 {
				continue
			}
			listener.OnProgress(m.bytes.Load(), time.Duration(m.now()-first).Milliseconds())
		}
	}
}
