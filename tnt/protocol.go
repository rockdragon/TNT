package tnt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
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

	// TrafficType 0: meaningless, 1: request, 2: response,  other: invalid
	TrafficType uint8

	// Traffic represent traffic throughout c/s
	Traffic struct {
		Type       TrafficType
		PayloadLen uint16 // length of payload
		Payload    []byte // rawaddr
	}
)

const (
	TrafficMeaningless TrafficType = iota
	TrafficRequest
)

const (
	layoutType       = 0
	layoutPayloadLen = 1
	layoutPayload    = 3
	lenType          = 1
	lenPayloadLen    = 2
	requestBuf       = 269
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

// NewTraffic payload stand for:
// rawaddr + payload
func NewTraffic(tp TrafficType, payload []byte) (r *Traffic) {
	return &Traffic{
		Type:       tp,
		PayloadLen: uint16(len(payload)),
		Payload:    payload,
	}
}

func (r *Traffic) Bytes() []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(uint8(r.Type))
	binary.Write(buf, binary.BigEndian, r.PayloadLen)
	buf.Write(r.Payload)
	return buf.Bytes()
}

// UnMarshalTraffic unmarshal TNTrequest via conn
func UnMarshalTraffic(conn io.Reader) (request *Traffic, err error) {
	buf := make([]byte, requestBuf)

	if _, err = io.ReadFull(conn, buf[:layoutType+lenType]); err != nil {
		return
	}
	tp := uint8(buf[layoutType])
	if tp > uint8(TrafficRequest) {
		err = fmt.Errorf("Invalid request type: %v", tp)
		return
	}

	if _, err = io.ReadFull(conn, buf[layoutPayloadLen:layoutPayloadLen+lenPayloadLen]); err != nil {
		return
	}
	lenPayload := binary.BigEndian.Uint16(buf[layoutPayloadLen : layoutPayloadLen+lenPayloadLen])

	if _, err = io.ReadFull(conn, buf[layoutPayload:layoutPayload+lenPayload]); err != nil {
		return
	}
	payload := buf[layoutPayload : layoutPayload+lenPayload]

	request = new(Traffic)
	request.Type = TrafficType(tp)
	request.PayloadLen = lenPayload
	request.Payload = payload

	return
}
