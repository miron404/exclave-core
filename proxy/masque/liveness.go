package masque

import (
	"context"
	"sync/atomic"
	"time"
)

// Variables only so that tests can shorten them.
var (
	// livenessWait is how long an HTTP/2 session may send without hearing
	// anything back before the endpoint is asked whether it is still there.
	livenessWait = 10 * time.Second
	// livenessPingTimeout is how long the answer may take.
	livenessPingTimeout = 10 * time.Second
)

// liveness finds an HTTP/2 session whose path has died, without spending
// anything while the tunnel is idle.
//
// The tunnel request stays open for the life of the session, so a path that
// dies silently would park both pumps on a connection that never delivers
// again, with no error to end them. A periodic ping catches that, but wakes the
// radio every period whether or not anything is going on. This one only looks
// when it matters: when something was sent and nothing at all has come back
// within livenessWait. Then a ping, answered by the endpoint itself, tells a
// dead path from a quiet destination, through every proxy in a chain, and a
// session that does not answer is closed so that the tunnel redials.
//
// The socket's TCP user timeout finds the same failure on a direct path; this
// covers a path through another proxy, whose far side no socket option here
// reaches.
type liveness struct {
	ping func(context.Context) error
	fail func(error)

	// received counts packets read from the session.
	received atomic.Uint64
	// armed is set while a check is pending, so that a stream of sends arms
	// one timer rather than one each.
	armed   atomic.Bool
	stopped atomic.Bool
}

func newLiveness(ping func(context.Context) error, fail func(error)) *liveness {
	return &liveness{ping: ping, fail: fail}
}

// sent notes that a packet went out. It is called for every packet, so all it
// does in the common case is one atomic load.
func (l *liveness) sent() {
	if l == nil || l.armed.Load() || !l.armed.CompareAndSwap(false, true) {
		return
	}
	mark := l.received.Load()
	time.AfterFunc(livenessWait, func() { l.check(mark) })
}

// heard notes that a packet came in.
func (l *liveness) heard() {
	if l != nil {
		l.received.Add(1)
	}
}

func (l *liveness) check(mark uint64) {
	defer l.armed.Store(false)
	if l.stopped.Load() || l.received.Load() != mark {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), livenessPingTimeout)
	defer cancel()
	err := l.ping(ctx)
	if err != nil && !l.stopped.Load() && l.received.Load() == mark {
		l.fail(err)
	}
}

// stop retires the check along with its session.
func (l *liveness) stop() {
	if l != nil {
		l.stopped.Store(true)
	}
}
