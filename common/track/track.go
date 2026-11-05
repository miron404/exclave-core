package track

import (
	"container/list"
	"io"
	"sync"
)

type ConnectionPool struct {
	mu   sync.Mutex
	list list.List
}

func NewConnectionPool() *ConnectionPool {
	return new(ConnectionPool)
}

func (p *ConnectionPool) PushBack(closer io.Closer) *list.Element {
	p.mu.Lock()
	elem := p.list.PushBack(closer)
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
	closers := make([]io.Closer, 0, p.list.Len())
	for elem := p.list.Front(); elem != nil; {
		nextElem := elem.Next()
		closers = append(closers, elem.Value.(io.Closer))
		_ = p.list.Remove(elem)
		elem = nextElem
	}
	p.mu.Unlock()
	for _, closer := range closers {
		closer.Close()
	}
}
