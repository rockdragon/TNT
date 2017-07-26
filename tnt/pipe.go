package tnt

import (
	"bytes"
	"log"
	"net"
	"strconv"
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

// HTTPProtocolHeader ...
func HTTPProtocolHeader(domain string) string {
	return strings.Join([]string{"GET / HTTP/1.1\r\n",
		"Host: " + domain + "\r\n",
		"Connection: Close\r\n",
		"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6)\r\n\r\n"}, "")
}

// ConnectWithHTTP ...
func ConnectWithHTTP(domain string, port int) (remote net.Conn, err error) {
	remote, err = net.Dial("tcp", domain+":"+strconv.Itoa(port))
	if err != nil {
		return
	}

	_, err = remote.Write([]byte(HTTPProtocolHeader(domain)))

	return
}
