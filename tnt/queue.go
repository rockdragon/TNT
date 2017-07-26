package tnt

import "errors"

// Queue for generic purpose
type Queue struct {
	queue    []interface{}
	capacity uint
	head     uint
	tail     uint
	size     uint
}

func (q *Queue) Push(elem interface{}) (err error) {
	if q.size == q.capacity {
		err = errors.New("Queue is full")
		return
	}
	q.queue = append(q.queue, elem)
	q.size = uint(len(q.queue))
	q.tail = q.size - 1
	return
}

func (q *Queue) Pop() (elem interface{}) {
	if q.size == 0 {
		return nil
	}
	elem = q.queue[q.tail]
	q.queue = q.queue[:q.tail]
	q.size = uint(len(q.queue))
	q.tail = q.size - 1
	return
}

func NewQueue(capacity uint) (queue *Queue) {
	return &Queue{
		queue:    make([]interface{}, capacity),
		capacity: capacity,
		head:     0,
		tail:     0,
		size:     0,
	}
}
