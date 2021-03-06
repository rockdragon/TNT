package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"

	tnt "github.com/rockdragon/TNT/tnt"
)

const (
	network       = "tcp"
	requestBuf    = 269
	maxNBuf       = 2048
	queueCapacity = 256

	socksVersion     = 5
	layoutVer        = 0
	layoutNofMethods = 1
	layoutMethods    = 2
	layoutCommand    = 1
	layoutRSV        = 2
	layoutATYP       = 3
	layoutAddr       = 4
	typeConnect      = 1

	typeIPv4   = uint8(1)                // type is ipv4 address
	typeDomain = uint8(3)                // type is domain address
	typeIPv6   = uint8(4)                // type is ipv6 address
	lenIPv4    = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
	lenIPv6    = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
	lenDmBase  = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
)

var (
	rawAddr      []byte
	httpHeader   []byte
	requestQueue = tnt.NewQueue(queueCapacity)
	config       *tnt.Config
	errNS        error
	cipher       *tnt.Cipher
	shutdown     chan struct{}
)

func init() {
	rand.Seed(time.Now().Unix())
}

func reply(conn net.Conn, bytes []byte) (err error) {
	if _, err := conn.Write(bytes); err != nil {
		log.Println("[RESP Error]", err)
	}
	return
}

// extract method negotiation header
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
func extractNegotiation(conn net.Conn) (socks *tnt.Socks5Negotiation, err error) {
	buf := make([]byte, requestBuf)

	if _, err = io.ReadFull(conn, buf[:layoutNofMethods+1]); err != nil {
		return
	}

	version := uint8(buf[layoutVer])
	if version != 5 {
		err = errors.New("NOT a Socks5 request")
		return
	}
	nOfMethods := uint8(buf[layoutNofMethods])
	if nOfMethods == 0 {
		// do nothing
	} else if _, err = io.ReadFull(conn, buf[layoutMethods:layoutMethods+nOfMethods]); err != nil {
		return
	}

	socks = new(tnt.Socks5Negotiation)
	socks.Version = version
	socks.NumOfMethods = nOfMethods

	for i := uint8(0); i < nOfMethods; i++ {
		method := uint8(buf[layoutMethods+i])
		socks.Methods = append(socks.Methods, method)
	}

	return
}

// extract socks5 request
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
func extractRequest(conn net.Conn) (socksReq *tnt.Socks5Request, err error) {
	buf := make([]byte, requestBuf)

	if _, err = io.ReadFull(conn, buf[:layoutATYP+1]); err != nil {
		return
	}

	version := uint8(buf[layoutVer])
	if version != 5 {
		err = errors.New("NOT a socks5 request")
		return
	}
	command := uint8(buf[layoutCommand])
	if command != typeConnect {
		err = errors.New("only CONNECT be able to accept")
		return
	}
	RSV := uint8(buf[layoutRSV])
	ATYP := uint8(buf[layoutATYP])
	var address string
	var addrEnd int
	var reqLen int

	switch ATYP {
	case typeIPv4:
		if _, err = io.ReadFull(conn, buf[layoutAddr:layoutAddr+lenIPv4]); err != nil {
			return
		}
		addrEnd = layoutAddr + lenIPv4
		address = net.IP(buf[layoutAddr:addrEnd]).String()
		reqLen = lenIPv4
	case typeIPv6:
		if _, err = io.ReadFull(conn, buf[layoutAddr:layoutAddr+lenIPv6]); err != nil {
			return
		}
		addrEnd = layoutAddr + lenIPv6
		address = net.IP(buf[layoutAddr:addrEnd]).String()
		reqLen = lenIPv6
	case typeDomain:
		if _, err = io.ReadFull(conn, buf[layoutAddr:layoutAddr+1]); err != nil {
			return
		}
		addrLen := int(buf[layoutAddr])
		addrEnd = layoutAddr + 1 + addrLen
		reqLen = addrLen + lenDmBase
		if _, err = io.ReadFull(conn, buf[layoutAddr+1:addrEnd]); err != nil {
			return
		}
		address = string(buf[layoutAddr+1 : addrEnd])
	default:
		err = fmt.Errorf("address type is Unknown: %d", ATYP)
		return
	}

	if _, err = io.ReadFull(conn, buf[addrEnd:addrEnd+2]); err != nil {
		return
	}

	socksReq = new(tnt.Socks5Request)
	socksReq.Version = version
	socksReq.Command = command
	socksReq.RSV = RSV
	socksReq.AddressType = ATYP
	socksReq.Address = address
	socksReq.Port = binary.BigEndian.Uint16(buf[addrEnd : addrEnd+2])
	socksReq.AddressWithPort = net.JoinHostPort(address, strconv.Itoa(int(socksReq.Port)))
	socksReq.RawAddr = buf[layoutATYP:reqLen]
	return
}

// reply the method selection
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
func replyNegotiation(conn net.Conn, socks *tnt.Socks5Negotiation) {
	// no authentication required
	reply(conn, []byte{socksVersion, 0x00})
}

// reply the request
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
func replyRequest(conn net.Conn, socksRequest *tnt.Socks5Request) {
	reply(conn, []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80, 0x88})
}

func sendMeaninglessPayload(cipher *tnt.Cipher) {
	remote, err := tnt.ConnectToServer(network, config.ServerAddr,
		tnt.TrafficMeaningless, rawAddr, cipher)
	if err != nil {
		log.Println("Connect to target server failed", err)
		return
	}
	requestQueue.Push(struct{}{})
	defer func() {
		requestQueue.Pop()
		remote.Close()
	}()

	go tnt.Pour(remote, httpHeader)
	tnt.Drain(remote)
}

func eventLoop(cipher *tnt.Cipher) {
	ticker := time.NewTicker(1 * time.Second)
	defer func() {
		ticker.Stop()
	}()

	for {
		select {
		case <-ticker.C:
			// log.Println("[TICKER]", requestQueue.Size())
			if requestQueue.Size() == 0 {
				sendMeaninglessPayload(cipher.Copy())
			}
		case <-shutdown:
			break
		}
	}
}

// rountine of per connection
// https://www.ietf.org/rfc/rfc1928.txt
func handleConn(conn net.Conn, cipher *tnt.Cipher) {
	defer conn.Close()

	// 1. extract info about negotiation
	socks, err := extractNegotiation(conn)
	if err != nil {
		log.Println("[Negotiate Request Error]", err)
		return
	}
	log.Println(socks)

	// 2. confirm negotiation
	replyNegotiation(conn, socks)

	// 3. extract info about request
	socksRequest, err := extractRequest(conn)
	if err != nil {
		log.Println("[Extract Request Error]", err)
		return
	}
	log.Println(socksRequest)

	// 4. confirm the connection was established
	replyRequest(conn, socksRequest)

	// 5. connect to remote
	remote, err := tnt.ConnectToServer(network, config.ServerAddr,
		tnt.TrafficRequest, socksRequest.RawAddr, cipher)
	if err != nil {
		log.Println("Connect to target server failed", err)
		return
	}
	requestQueue.Push(struct{}{})
	defer func() {
		requestQueue.Pop()
		remote.Close()
	}()

	go tnt.Pipe(conn, remote)
	tnt.Pipe(remote, conn)

	return
}

func main() {
	cfgfile := flag.String("c", "config.json", "config file path")
	flag.Parse()

	config, errNS = tnt.ParseConfig(*cfgfile)
	if errNS != nil {
		log.Println("Config Parse Error", errNS)
		os.Exit(1)
	}
	log.Println("[CONF]", config)

	rawAddr = tnt.RawAddr(config.TargetDomain, config.TargetPort)
	httpHeader = tnt.HTTPProtocolHeader(config.TargetDomain)

	log.Println("Server is Listening:", network, config.LocalAddr)
	ln, err := net.Listen(network, config.LocalAddr)
	if err != nil {
		log.Println("Listen Error", err)
		os.Exit(1)
	}

	cipher, err := tnt.NewCipher(config.Method, config.Password)
	if err != nil {
		log.Println("Generate Cipher Error", err)
		os.Exit(1)
	}

	go eventLoop(cipher)
	defer func() {
		shutdown <- struct{}{}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept Rrror: %v\n", err)
			continue
		}

		go handleConn(conn, cipher.Copy())
	}
}
