package tnt

import (
	"bytes"
	"fmt"
)

type (
	Socks5Negotiation struct {
		Version      uint8
		NumOfMethods uint8
		Methods      []uint8
	}

	Socks5Request struct {
		Version         uint8
		Command         uint8
		RSV             uint8
		AddressType     uint8
		Address         string
		Port            uint16
		AddressWithPort string
		RawAddr         []byte
	}
)

func methodMeaning(n uint8) (result string) {
	switch n {
	case 0x00:
		result = "NO AUTHENTICATION REQUIRED"
	case 0x01:
		result = "GSSAPI"
	case 0x02:
		result = "USERNAME/PASSWORD"
	case 0x03:
		result = "to X'7F' IANA ASSIGNED"
	case 0x80:
		result = "to X'FE' RESERVED FOR PRIVATE METHODS"
	default:
		result = `illegal method of ${n}`
	}
	return
}

func commandMeaning(n uint8) (result string) {
	switch n {
	case 0x01:
		result = "CONNECT"
	case 0x02:
		result = "BIND"
	case 0x03:
		result = "UDP ASSOCIATE"
	default:
		result = "Unknown Command"
	}
	return
}

func (s *Socks5Negotiation) String() string {
	var buf bytes.Buffer
	buf.WriteString("[Socks5 Negotiation]")
	if s.NumOfMethods > 0 {
		for i := uint8(0); i < s.NumOfMethods; i++ {
			buf.WriteString(fmt.Sprintf(" [%v]", methodMeaning(s.Methods[i])))
		}
	}
	return buf.String()
}

func (s *Socks5Request) String() string {
	var buf bytes.Buffer
	buf.WriteString("[Socks5 Request]")
	buf.WriteString(fmt.Sprintf(" [Command:%s]", commandMeaning(s.Command)))
	buf.WriteString(fmt.Sprintf(" [%s]", s.AddressWithPort))
	return buf.String()
}
