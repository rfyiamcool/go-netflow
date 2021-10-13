package netflow

import (
	"errors"
	"sync"
)

var (
	ErrQueueFull = errors.New("queue is full")
)

type ringQueue struct {
	sync.RWMutex
	buf               []interface{}
	head, tail, count int
}

func newRingQueue(size int) *ringQueue {
	return &ringQueue{
		buf: make([]interface{}, size),
	}
}

func (q *ringQueue) Length() int {
	return q.count
}

func (q *ringQueue) Add(elem interface{}) error {
	q.Lock()
	defer q.Unlock()

	if q.count == len(q.buf) {
		return ErrQueueFull
	}

	q.count++
	q.buf[q.tail] = elem

	if q.tail+1 < len(q.buf) {
		q.tail++
	}
	if len(q.buf) == q.count {
		q.tail = 0
	}
	return nil
}

func (q *ringQueue) Peek() interface{} {
	q.RLock()
	defer q.RUnlock()

	if q.count <= 0 {
		return nil
	}
	return q.buf[q.head]
}

func (q *ringQueue) Remove() interface{} {
	q.Lock()
	defer q.Unlock()

	if q.count <= 0 {
		return nil
	}

	ret := q.buf[q.head]
	q.buf[q.head] = nil

	q.head = (q.head + 1) & (len(q.buf) - 1)
	q.count--

	return ret
}
