package tnt

import (
	"io"
	"log"
	"net"
	"time"

	"github.com/satori/uuid"
)

type Conn struct {
	net.Conn
	*Cipher
	ID []byte // [16]byte
}

var (
	readTimeout = 120 * time.Second
	zeroByte    = make([]byte, 0)
)

func (c *Conn) Close() error {
	return c.Conn.Close()
}
func (c *Conn) Read(b []byte) (n int, err error) {
	defer HandlePanic()

	if c.dec == nil {
		log.Println("no dec, auto gen a dec.")
		iv := make([]byte, c.info.ivLen)
		if _, err = io.ReadFull(c.Conn, iv); err != nil {
			return
		}
		if err = c.initDecrpt(iv); err != nil {
			return
		}
		if len(c.iv) == 0 {
			c.iv = iv
		}
	}

	buf := make([]byte, len(b))
	n, err = c.Conn.Read(buf)
	if n > 0 {
		c.decrypt(b[:n], buf[:n])
		log.Printf("[DEC] %d %v -> %v [IV] %v \n", n, buf[:n], b[:n], c.iv)
	}
	return
}
func (c *Conn) Write(b []byte) (n int, err error) {
	n, err = c.writeWithCipher(b)
	return
}

func setReadTimeout(c net.Conn) {
	if readTimeout != 0 {
		c.SetReadDeadline(time.Now().Add(readTimeout))
	}
}
func (c *Conn) SetReadTimeout() {
	setReadTimeout(c.Conn)
}

func NewConn(c net.Conn, cipher *Cipher) *Conn {
	return &Conn{
		Conn:   c,
		Cipher: cipher,
		ID:     uuid.NewV1().Bytes(),
	}
}

func (c *Conn) writeWithCipher(b []byte) (n int, err error) {
	var iv []byte
	if c.enc == nil {
		iv, err = c.initEncrpyt()
		if err != nil {
			return
		}
	}

	dataLen := len(b) + len(iv)
	buf := make([]byte, dataLen)
	if iv != nil {
		copy(buf, iv)
	}
	c.encrypt(buf[len(iv):], b)
	n, err = c.Conn.Write(buf)
	log.Printf("[write] %v -> %v [iv] %v\n", b, buf, iv)
	return
}

// Ping test connectivity
func Ping(c net.Conn) (result bool) {
	if c == nil {
		return false
	}
	c.SetReadDeadline(time.Now())
	if _, err := c.Read(zeroByte); err != nil {
		log.Print("[CONN ERROR]", err)
		c.Close()
		c = nil
		result = false
	} else {
		setReadTimeout(c)
		result = true
	}
	return
}

// ConnectToServer one connction version
func ConnectToServer(network, addr string, cipher *Cipher) (c *Conn, err error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return
	}
	c = NewConn(conn, cipher)

	return
}
