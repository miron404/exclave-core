package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	gonet "net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func shortLiveness(t *testing.T) {
	wait, timeout := livenessWait, livenessPingTimeout
	livenessWait, livenessPingTimeout = 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { livenessWait, livenessPingTimeout = wait, timeout })
}

// The check only pings when something went out and nothing came back, pings
// once however much went out, and gives the session up only when the ping
// fails.
func TestLivenessPingsOnlyWhenNothingCameBack(t *testing.T) {
	shortLiveness(t)
	var pings atomic.Int32
	pingErr := atomic.Pointer[error]{}
	failed := make(chan error, 1)
	l := newLiveness(func(context.Context) error {
		pings.Add(1)
		if err := pingErr.Load(); err != nil {
			return *err
		}
		return nil
	}, func(err error) { failed <- err })

	// Answered: no ping.
	l.sent()
	l.heard()
	time.Sleep(4 * livenessWait)
	if pings.Load() != 0 {
		t.Fatal("pinged although an answer came back")
	}

	// Unanswered but alive: one ping for many sends, and no failure.
	for range 100 {
		l.sent()
	}
	time.Sleep(4 * livenessWait)
	if pings.Load() != 1 {
		t.Fatalf("pinged %d times, want 1", pings.Load())
	}
	select {
	case err := <-failed:
		t.Fatal("failed although the ping was answered: ", err)
	default:
	}

	// Unanswered and dead: the session is given up.
	dead := errors.New("no answer")
	pingErr.Store(&dead)
	l.sent()
	select {
	case err := <-failed:
		if !errors.Is(err, dead) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("a session that did not answer was kept")
	}

	// A retired session is not checked any more.
	l.stop()
	before := pings.Load()
	l.sent()
	time.Sleep(4 * livenessWait)
	if pings.Load() != before {
		t.Fatal("a stopped session was pinged")
	}
}

// freezingRelay forwards TCP until frozen, then holds both connections open
// and passes nothing, the way a proxy does whose own path onwards has died.
type freezingRelay struct {
	listener gonet.Listener
	frozen   chan struct{}
	once     sync.Once
}

func newFreezingRelay(t *testing.T, target string) *freezingRelay {
	listener, err := gonet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &freezingRelay{listener: listener, frozen: make(chan struct{})}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			server, err := gonet.Dial("tcp", target)
			if err != nil {
				_ = client.Close()
				continue
			}
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			go r.pipe(server, client)
			go r.pipe(client, server)
		}
	}()
	return r
}

func (r *freezingRelay) pipe(dst io.Writer, src io.Reader) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		select {
		case <-r.frozen:
			// Swallow everything from now on.
			if err != nil {
				return
			}
			continue
		default:
		}
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (r *freezingRelay) freeze() { r.once.Do(func() { close(r.frozen) }) }

// Through a proxy whose onward path dies, the connection to the proxy stays
// healthy and no socket option can tell. The ping is answered by the endpoint
// itself, so it goes unanswered, and the session is given up.
func TestLivenessFindsAPathThatDiedBeyondAProxy(t *testing.T) {
	shortLiveness(t)
	serverTLS, _ := testTLS(t)
	serverTLS.NextProtos = []string{"h2"}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		_ = (&http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}).Serve(listener)
	}()

	relay := newFreezingRelay(t, listener.Addr().String())
	rawConn, err := gonet.Dial("tcp", relay.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	h2Conn, err := (&http2.Transport{}).NewClientConn(tlsConn)
	if err != nil {
		t.Fatal(err)
	}
	defer h2Conn.Close()

	failed := make(chan error, 1)
	l := newLiveness(h2Conn.Ping, func(err error) { failed <- err })

	// Alive: the ping goes through the relay and is answered.
	l.sent()
	select {
	case err := <-failed:
		t.Fatal("gave up a live session: ", err)
	case <-time.After(4 * livenessWait):
	}

	relay.freeze()
	l.sent()
	select {
	case <-failed:
	case <-time.After(livenessWait + livenessPingTimeout + time.Second):
		t.Fatal("a session behind a dead path was kept")
	}
}
