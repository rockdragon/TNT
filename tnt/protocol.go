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

	TNTRequest struct {
		Type    uint8     // 0: meaningless, 1: valid, other: invalid
		ID      uuid.UUID // UUID identify a request, length:16
		Length  uint16    // length of payload
		Payload []byte
	}
)

const (
	layoutType    = 0
	layoutID      = 1
	layoutLength  = 17
	layoutPayload = 19
	lenType       = 1
	lenID         = 16
	lenLength     = 2
	lenPayload    = 255
	requestBuf    = lenType + lenID + lenLength + lenPayload
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

func NewTNTRequest(tp uint8, rawaddr []byte) (r *TNTRequest) {
	return &TNTRequest{
		Type:    tp,
		ID:      uuid.NewV1(),
		Length:  uint16(len(rawaddr)),
		Payload: rawaddr,
	}
}

func (r *TNTRequest) Bytes() []byte {
	buf := new(bytes.Buffer)
	buf.Write(r.ID.Bytes())
	buf.WriteByte(r.Type)
	binary.Write(buf, binary.BigEndian, r.Length)
	buf.Write(r.Payload)
	return buf.Bytes()
}

// UnMarshalRequest unmarshal TNTrequest via conn
func UnMarshalRequest(conn io.Reader) (request *TNTRequest, err error) {
	buf := make([]byte, requestBuf)

	if _, err = io.ReadFull(conn, buf[:layoutType+lenType]); err != nil {
		return
	}
	tp := uint8(buf[layoutType])
	if tp > 1 {
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

	if _, err = io.ReadFull(conn, buf[layoutLength:layoutLength+lenLength]); err != nil {
		return
	}
	lenPayload := binary.BigEndian.Uint16(buf[layoutLength : layoutLength+lenLength])

	if _, err = io.ReadFull(conn, buf[layoutPayload:layoutPayload+lenPayload]); err != nil {
		return
	}

	request = new(TNTRequest)
	request.Type = tp
	request.ID = u1
	request.Length = lenPayload
	request.Payload = buf[layoutPayload : layoutPayload+lenPayload]
	return
}
