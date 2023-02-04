package utils

import (
	"sync"
)

type PSTopicType string

// PSAgent is a simple pub/sub PSAgent
type PSAgent struct {
	mu     sync.Mutex
	subs   map[PSTopicType][]chan interface{}
	quit   chan struct{}
	closed bool
}

// NewPSAgent creates a new Agent
func NewAgent() *PSAgent {
	return &PSAgent{
		subs: make(map[PSTopicType][]chan interface{}),
		quit: make(chan struct{}),
	}
}

// Publish publishes a message to a topic
func (b *PSAgent) Publish(topic PSTopicType, msg interface{}) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}

	for _, ch := range b.subs[topic] {
		ch <- msg
	}
}

// Subscribe subscribes to a topic
func (b *PSAgent) Subscribe(topic PSTopicType) <-chan interface{} {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	ch := make(chan interface{})
	b.subs[topic] = append(b.subs[topic], ch)
	return ch
}

// Close closes the PSAgent
func (b *PSAgent) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}

	b.closed = true
	close(b.quit)

	for _, ch := range b.subs {
		for _, sub := range ch {
			close(sub)
		}
	}
}
