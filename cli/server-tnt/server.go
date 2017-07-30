package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	tnt "github.com/rockdragon/TNT/tnt"
)

const (
	network    = "tcp"
	raddr      = ":10086"
	password   = "$RGB&*()$RGN!@#$"
	method     = "chacha20"
	requestBuf = 269

	layoutATYP = 0
	layoutIP   = 1
	layoutAddr = 1

	typeIPv4   = uint8(1)                // type is ipv4 address
	typeDomain = uint8(3)                // type is domain address
	typeIPv6   = uint8(4)                // type is ipv6 address
	lenIPv4    = 3 + 1 + net.IPv4len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
	lenIPv6    = 3 + 1 + net.IPv6len + 2 // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
	lenDmBase  = 3 + 1 + 1 + 2           // 3 + 1addrType + 1addrLen + 2port, plus addrLen
)

func extractRequest(conn *tnt.Conn) (host string, err error) {
	conn.SetReadTimeout()

	traffic, err := tnt.UnMarshalTraffic(conn)
	if err != nil {
		return
	}

	log.Println("[Traffic Payload]", traffic.Payload)
	buf := traffic.Payload
	ATYP := uint8(buf[layoutATYP])
	var address string
	var addrEnd int

	switch ATYP {
	case typeIPv4:
		addrEnd = layoutAddr + lenIPv4
		address = net.IP(buf[layoutAddr:addrEnd]).String()
	case typeIPv6:
		addrEnd = layoutAddr + lenIPv6
		address = net.IP(buf[layoutAddr:addrEnd]).String()
	case typeDomain:
		addrLen := int(buf[layoutAddr])
		addrEnd = layoutAddr + 1 + addrLen
		address = string(buf[layoutAddr+1 : addrEnd])
	default:
		err = fmt.Errorf("address type is Unknown: %d", ATYP)
		return
	}

	port := binary.BigEndian.Uint16(buf[addrEnd : addrEnd+2])
	host = net.JoinHostPort(address, strconv.Itoa(int(port)))
	return
}

func handleConn(conn *tnt.Conn) {
	defer conn.Close()

	// 1. extract host info
	host, err := extractRequest(conn)
	if err != nil {
		log.Println("Extract Request Error", err)
		return
	}
	log.Println("[HOST]", host)

	// 2. request to the remote
	remote, err := net.Dial(network, host)
	if err != nil {
		log.Println("Request Remote Error", err)
		return
	}
	defer remote.Close()

	go tnt.Pipe(conn, remote)
	tnt.Pipe(remote, conn)
}

func main() {
	log.Println("Server is Listening:", network, raddr)
	ln, err := net.Listen(network, raddr)
	if err != nil {
		log.Println("Listen Error", err)
		os.Exit(1)
	}
	var cipher *tnt.Cipher
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept Rrror: %v\n", err)
			return
		}
		if cipher == nil {
			cipher, err = tnt.NewCipher(method, password)
			if err != nil {
				log.Println("Generate Cipher Error", err)
				conn.Close()
				continue
			}
		}

		go handleConn(tnt.NewConn(conn, cipher.Copy()))
	}
}
