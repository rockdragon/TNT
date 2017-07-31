package tnt

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"strings"
)

const (
	maxNBuf = 2048
)

// Pipe ...
func Pipe(src, dst net.Conn) {
	buf := make([]byte, maxNBuf)
	for {
		setReadTimeout(src)
		// log.Println("CHUNK...")
		n, err := src.Read(buf)
		// log.Println("PIPE DATA: ", n, err)
		if n > 0 {
			if _, err = dst.Write(buf[0:n]); err != nil {
				log.Println("[PIPE DATA ERROR]", err)
				break
			}
		}
		if err != nil {
			break
		}
		// log.Println("FIN")
	}
}

// ReadStream ...
func ReadStream(conn net.Conn) *bytes.Buffer {
	result := new(bytes.Buffer)
	buf := make([]byte, maxNBuf)
	for {
		setReadTimeout(conn)
		n, err := conn.Read(buf)
		if n > 0 {
			result.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return result
}

// Drain stream
func Drain(conn net.Conn) {
	buf := make([]byte, maxNBuf)
	for {
		setReadTimeout(conn)
		_, err := conn.Read(buf)
		if err != nil {
			break
		}
	}
}

// Pour stream
func Pour(conn net.Conn, data []byte) {
	if _, err := conn.Write(data); err != nil {
		log.Println("[Pour data error]", err)
	}
}

// HTTPProtocolHeader ...
func HTTPProtocolHeader(domain string) []byte {
	return []byte(strings.Join([]string{"GET / HTTP/1.1\r\n",
		"Host: " + domain + "\r\n",
		"Connection: Close\r\n",
		"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6)\r\n\r\n"}, ""))
}

// RawAddr according to domain and port
func RawAddr(domain string, port uint16) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(uint8(3))
	buf.WriteByte(uint8(len(domain)))
	buf.Write([]byte(domain))
	binary.Write(buf, binary.BigEndian, port)
	return buf.Bytes()
}
