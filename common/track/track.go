package track

import (
	"container/list"
	"sync"
	"time"
)

type deadlineSetter interface {
	SetDeadline(t time.Time) error
}

type ConnectionPool struct {
	mu   sync.Mutex
	list list.List
}

func NewConnectionPool() *ConnectionPool {
	return new(ConnectionPool)
}

func (p *ConnectionPool) PushBack(deadlineSetter deadlineSetter) *list.Element {
	p.mu.Lock()
	elem := p.list.PushBack(deadlineSetter)
	p.mu.Unlock()
	return elem
}

func (p *ConnectionPool) Remove(elem *list.Element) {
	p.mu.Lock()
	_ = p.list.Remove(elem)
	p.mu.Unlock()
}

func (p *ConnectionPool) ResetConnections() {
	p.mu.Lock()
	deadlineSetters := make([]deadlineSetter, 0, p.list.Len())
	// Removing an element clears its link to the next one, so the next has
	// to be taken first, or only the first connection is ever reset.
	for elem := p.list.Front(); elem != nil; {
		next := elem.Next()
		deadlineSetters = append(deadlineSetters, elem.Value.(deadlineSetter))
		_ = p.list.Remove(elem)
		elem = next
	}
	p.mu.Unlock()
	now := time.Now()
	for _, deadlineSetter := range deadlineSetters {
		deadlineSetter.SetDeadline(now)
	}
}
