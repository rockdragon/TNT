package main

import (
	"log"
	"net"
	"os"
)

const (
	network = "tcp"
	raddr   = "127.0.0.1:10086"
)

func handleConn(conn net.Conn) {

}

func main() {
	log.Println("Server is Listening:", network, raddr)
	ln, err := net.Listen(network, raddr)
	if err != nil {
		log.Println("Listen Error", err)
		os.Exit(1)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept Rrror: %v\n", err)
			return
		}

		go handleConn(conn)
	}
}
