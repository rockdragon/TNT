package tnt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/satori/uuid"
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
		ID         uuid.UUID // UUID identify a request, length:16
		AddrLen    uint16    // length of raw addr
		Addr       []byte    // raw addr for request
		PayloadLen uint32    // length of payload
		Payload    []byte    // request/response data
	}
)

const (
	TrafficMeaningless TrafficType = iota
	TrafficRequest
	TrafficResponse
)

const (
	layoutType    = 0
	layoutID      = 1
	layoutAddrLen = 17
	layoutAddr    = 19
	lenType       = 1
	lenID         = 16
	lenAddrLen    = 2
	lenPayloadLen = 4
	requestBuf    = 65535
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
func NewTraffic(tp TrafficType, addr []byte, payload []byte) (r *Traffic) {
	return &Traffic{
		Type:       tp,
		ID:         uuid.NewV1(),
		AddrLen:    uint16(len(addr)),
		Addr:       addr,
		PayloadLen: uint32(len(payload)),
		Payload:    payload,
	}
}

func (r *Traffic) Bytes() []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(uint8(r.Type))
	buf.Write(r.ID.Bytes())
	binary.Write(buf, binary.BigEndian, r.AddrLen)
	buf.Write(r.Addr)
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
	if tp > uint8(TrafficResponse) {
		err = fmt.Errorf("Invalid request type: %v", tp)
		return
	}

	if _, err = io.ReadFull(conn, buf[layoutID:layoutID+lenID]); err != nil {
		return
	}
	u1 := uuid.UUID{}
	id := buf[layoutID : layoutID+lenID]
	if err = u1.Scan(id); err != nil { // is a valid UUID?
		return
	}

	if _, err = io.ReadFull(conn, buf[layoutAddrLen:layoutAddrLen+lenAddrLen]); err != nil {
		return
	}
	lenAddr := binary.BigEndian.Uint16(buf[layoutAddrLen : layoutAddrLen+lenAddrLen])

	if _, err = io.ReadFull(conn, buf[layoutAddr:layoutAddr+lenAddr]); err != nil {
		return
	}
	addr := buf[layoutAddr : layoutAddr+lenAddr]
	layoutPayloadLen := layoutAddr + lenAddr

	if _, err = io.ReadFull(conn, buf[layoutPayloadLen:layoutPayloadLen+lenPayloadLen]); err != nil {
		return
	}
	lenPayload := binary.BigEndian.Uint32(buf[layoutPayloadLen : layoutPayloadLen+lenPayloadLen])
	layoutPayload := uint32(layoutPayloadLen + lenPayloadLen)

	if _, err = io.ReadFull(conn, buf[layoutPayload:layoutPayload+lenPayload]); err != nil {
		return
	}
	payload := buf[layoutPayload : layoutPayload+lenPayload]

	request = new(Traffic)
	request.Type = TrafficType(tp)
	request.ID = u1
	request.AddrLen = lenAddr
	request.Addr = addr
	request.PayloadLen = lenPayload
	request.Payload = payload

	return
}
