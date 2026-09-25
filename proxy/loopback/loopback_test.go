package loopback

import (
	"context"
	"testing"

	"github.com/exclavenetwork/exclave-core/v5/common/errors"
	"github.com/exclavenetwork/exclave-core/v5/common/net"
	"github.com/exclavenetwork/exclave-core/v5/common/session"
	"github.com/exclavenetwork/exclave-core/v5/features/routing"
	"github.com/exclavenetwork/exclave-core/v5/transport"
	"github.com/exclavenetwork/exclave-core/v5/transport/pipe"
)

// recordingDispatcher remembers the inbound tag each dispatch was made with,
// and refuses the dispatch so that Process returns straight away.
type recordingDispatcher struct{ tags []string }

func (*recordingDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*recordingDispatcher) Start() error      { return nil }
func (*recordingDispatcher) Close() error      { return nil }

func (d *recordingDispatcher) Dispatch(ctx context.Context, _ net.Destination) (*transport.Link, error) {
	tag := "<none>"
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		tag = inbound.Tag
	}
	d.tags = append(d.tags, tag)
	return nil, errors.New("refused")
}

func process(t *testing.T, l *Loopback, ctx context.Context) {
	t.Helper()
	ctx = session.ContextWithOutbound(ctx, &session.Outbound{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 443),
	})
	reader, writer := pipe.New()
	if err := l.Process(ctx, &transport.Link{Reader: reader, Writer: writer}, nil); err == nil {
		t.Fatal("the refused dispatch was not reported")
	}
}

// A chain whose first hop is a loopback is probed by the observatory, which
// dials with no inbound in its context. That used to dereference nil.
func TestLoopbackWithoutAnInbound(t *testing.T) {
	dispatcher := &recordingDispatcher{}
	l := &Loopback{config: &Config{InboundTag: "front"}, dispatcherInstance: dispatcher}
	process(t, l, context.Background())
	if len(dispatcher.tags) != 1 || dispatcher.tags[0] != "front" {
		t.Fatalf("dispatched with inbound tags %v, want [front]", dispatcher.tags)
	}
}

// The inbound a connection carries belongs to the inbound that accepted it,
// so the loopback retags a copy and leaves the original alone.
func TestLoopbackLeavesTheOriginalInbound(t *testing.T) {
	dispatcher := &recordingDispatcher{}
	l := &Loopback{config: &Config{InboundTag: "front"}, dispatcherInstance: dispatcher}
	original := &session.Inbound{Tag: "tun"}
	process(t, l, session.ContextWithInbound(context.Background(), original))
	if dispatcher.tags[0] != "front" {
		t.Fatalf("dispatched with inbound tag %q, want front", dispatcher.tags[0])
	}
	if original.Tag != "tun" {
		t.Fatalf("the accepting inbound was retagged to %q", original.Tag)
	}
}
