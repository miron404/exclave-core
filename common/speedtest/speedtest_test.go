package speedtest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/exclavenetwork/exclave-core/v5"
	"github.com/exclavenetwork/exclave-core/v5/infra/conf/serial"
	_ "github.com/exclavenetwork/exclave-core/v5/main/distro/all"
)

// startInstance runs an instance the way the app does for a speed test: an
// ipc inbound on a unix socket, here in front of a direct outbound.
func startInstance(t *testing.T) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "speedtest.sock")
	config, err := serial.LoadJSONConfig(strings.NewReader(fmt.Sprintf(`{
		"inbounds": [{"tag": "speedtest-in", "protocol": "ipc", "listen": %q}],
		"outbounds": [{"protocol": "freedom"}]
	}`, socket)))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := core.New(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { instance.Close() })
	return socket
}

// endless sends chunks until the client goes, one every gap.
func endless(gap time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 16<<10)
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			if gap > 0 {
				select {
				case <-time.After(gap):
				case <-r.Context().Done():
					return
				}
			}
		}
	}
}

type progress struct{ calls atomic.Int32 }

func (p *progress) OnProgress(bytes int64, elapsedMillis int64) {
	p.calls.Add(1)
}

func TestRunStopsAtMaxBytes(t *testing.T) {
	socket := startInstance(t)
	server := httptest.NewServer(endless(0))
	defer server.Close()

	result, err := NewTest(socket).Run(server.URL, 4<<20, 1, 5000, 10000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Bytes < 4<<20 || result.Bytes > 4<<20+readSize {
		t.Fatalf("got %d bytes, want 4 MiB and at most one read more", result.Bytes)
	}
	if result.ConnectMillis <= 0 || result.ElapsedMillis <= 0 {
		t.Fatalf("times not measured: %+v", result)
	}
}

func TestRunStopsAtDuration(t *testing.T) {
	socket := startInstance(t)
	server := httptest.NewServer(endless(20 * time.Millisecond))
	defer server.Close()

	listener := new(progress)
	began := time.Now()
	result, err := NewTest(socket).Run(server.URL, 1<<40, 1, 5000, 1200, listener)
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(began); took > 3*time.Second {
		t.Fatalf("a 1.2 s test took %v", took)
	}
	if result.ElapsedMillis < 1100 || result.ElapsedMillis > 1500 {
		t.Fatalf("window was %d ms, want about 1200", result.ElapsedMillis)
	}
	if listener.calls.Load() == 0 {
		t.Fatal("no progress reported")
	}
}

// A response that ends before the time is up is measured to its last byte,
// not to the end of the window.
func TestRunMeasuresShortResponseToItsEnd(t *testing.T) {
	socket := startInstance(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 1<<20))
	}))
	defer server.Close()

	result, err := NewTest(socket).Run(server.URL, 1<<40, 1, 5000, 5000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Bytes != 1<<20 {
		t.Fatalf("got %d bytes, want 1 MiB", result.Bytes)
	}
	if result.ElapsedMillis > 1000 {
		t.Fatalf("window was %d ms, but the response ended right away", result.ElapsedMillis)
	}
}

func TestRunOpensSeparateConnections(t *testing.T) {
	socket := startInstance(t)
	var mu sync.Mutex
	peers := make(map[string]bool)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		peers[r.RemoteAddr] = true
		mu.Unlock()
		endless(0)(w, r)
	}))
	defer server.Close()

	// The freedom outbound sets a field of its own on its first connection,
	// which the race detector catches when several make the first at once.
	if _, err := NewTest(socket).Run(server.URL, 1, 1, 5000, 10000, nil); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	clear(peers)
	mu.Unlock()
	if _, err := NewTest(socket).Run(server.URL, 8<<20, 4, 5000, 10000, nil); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if n := len(peers); n != 4 {
		t.Fatalf("server saw %d connections, want 4", n)
	}
}

func TestRunReportsHTTPError(t *testing.T) {
	socket := startInstance(t)
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	_, err := NewTest(socket).Run(server.URL, 1<<20, 1, 5000, 1000, nil)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("got %v, want the 404", err)
	}
}

func TestRunTimesOutConnecting(t *testing.T) {
	socket := startInstance(t)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	began := time.Now()
	_, err := NewTest(socket).Run(server.URL, 1<<20, 1, 500, 10000, nil)
	if err != errConnectTimeout {
		t.Fatalf("got %v, want the connect timeout", err)
	}
	if took := time.Since(began); took > 2*time.Second {
		t.Fatalf("a 500 ms connect timeout took %v", took)
	}
}

func TestCancel(t *testing.T) {
	socket := startInstance(t)
	server := httptest.NewServer(endless(10 * time.Millisecond))
	defer server.Close()

	test := NewTest(socket)
	time.AfterFunc(300*time.Millisecond, test.Cancel)
	began := time.Now()
	_, err := test.Run(server.URL, 1<<40, 1, 5000, 30000, nil)
	if err != errCanceled {
		t.Fatalf("got %v, want canceled", err)
	}
	if took := time.Since(began); took > 2*time.Second {
		t.Fatalf("canceling took %v", took)
	}
}
