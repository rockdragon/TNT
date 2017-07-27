package tnt

import (
	"net"

	"github.com/satori/uuid"
)

// ConnMap ...
type ConnMap map[uuid.UUID]net.Conn

func NewConnMap(capacity int) (c ConnMap) {
	return make(ConnMap, capacity)
}

func (c ConnMap) Get(k uuid.UUID) (conn net.Conn, ok bool) {
	conn, ok = c[k]
	return
}

func (c ConnMap) Set(k uuid.UUID, conn net.Conn) {
	c[k] = conn
}

func (c ConnMap) Delete(k uuid.UUID) {
	_, ok := c[k]
	if ok {
		delete(c, k)
	}
}
