package track

import "testing"

type recorder struct{ closed bool }

func (r *recorder) Close() error {
	r.closed = true
	return nil
}

// Every connection in the pool is reset, not only the first, and one that
// closes afterwards still removes itself cleanly.
func TestResetConnectionsResetsAll(t *testing.T) {
	p := NewConnectionPool()
	conns := make([]*recorder, 5)
	for i := range conns {
		conns[i] = new(recorder)
		p.PushBack(conns[i])
	}
	late := new(recorder)
	lateElem := p.PushBack(late)

	p.ResetConnections()
	for i, c := range conns {
		if !c.closed {
			t.Fatalf("connection %d of %d was not reset", i, len(conns)+1)
		}
	}
	if !late.closed {
		t.Fatal("the last connection was not reset")
	}
	if n := p.list.Len(); n != 0 {
		t.Fatalf("%d connections still held after a reset", n)
	}
	p.Remove(lateElem)
	if n := p.list.Len(); n != 0 {
		t.Fatalf("removing a reset connection left the pool at %d", n)
	}
}
