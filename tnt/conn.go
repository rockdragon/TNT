package tnt

import (
	"io"
	"net"
)

type Conn struct {
	net.Conn
	*Cipher
}

func (c *Conn) Close() error {
	return c.Conn.Close()
}
func (c *Conn) Read(b []byte) (n int, err error) {
	if c.dec == nil {
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

	buf := make([]byte, maxNBuf)
	n, err = c.Conn.Read(buf)
	if n > 0 {
		c.decrypt(b[:n], buf[:n])
	}
	return
}
func (c *Conn) Write(b []byte) (n int, err error) {
	n, err = c.writeWithCipher(b)
	return
}

func NewConn(c net.Conn, cipher *Cipher) *Conn {
	return &Conn{
		Conn:   c,
		Cipher: cipher,
	}
}

func ConnectToServer(network, addr string, rawaddr []byte, cipher *Cipher) (c *Conn, err error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return
	}
	c = NewConn(conn, cipher)
	if _, err = c.writeWithCipher(rawaddr); err != nil {
		c.Close()
		return nil, err
	}
	return
}

func (c *Conn) writeWithCipher(b []byte) (n int, err error) {
	var iv []byte
	if c.enc == nil {
		iv, err = c.initEncrpyt()
		if err != nil {
			return
		}
	}
	buf := make([]byte, maxNBuf)
	if iv != nil {
		copy(buf, iv)
	}

	c.encrypt(buf[len(iv):], b)
	n, err = c.Conn.Write(buf)
	return
}
