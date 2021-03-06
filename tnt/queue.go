package tnt

import (
	"errors"
	"sync"
)

var queueLock *sync.RWMutex

// Queue for generic purpose
type Queue struct {
	queue    []interface{}
	capacity uint
	head     uint
	tail     uint
	size     uint
}

func NewQueue(capacity uint) (queue *Queue) {
	queueLock = new(sync.RWMutex)
	return &Queue{
		queue:    make([]interface{}, 0, capacity),
		capacity: capacity,
		head:     0,
		tail:     0,
		size:     0,
	}
}

func (q *Queue) Size() (size uint) {
	queueLock.RLock()
	size = q.size
	queueLock.RUnlock()
	return
}

func (q *Queue) Push(elem interface{}) (err error) {
	queueLock.Lock()
	// log.Println("Push")
	if q.size == q.capacity {
		err = errors.New("Queue is full")
		return
	}
	q.queue = append(q.queue, elem)
	q.size = uint(len(q.queue))
	q.tail = q.size - 1
	queueLock.Unlock()
	return
}

func (q *Queue) Pop() (elem interface{}) {
	queueLock.Lock()
	// log.Println("Pop")
	if q.size == 0 {
		return nil
	}
	elem = q.queue[q.tail]
	q.queue = q.queue[:q.tail]
	q.size = uint(len(q.queue))
	q.tail = q.size - 1
	queueLock.Unlock()
	return
}
