package parser

import (
	"errors"
	"fmt"
)

const ldapTagSequence = 0x30
const ldapTagInteger = 0x02
const ldapProtoSearchResultDone = 0x65

type LDAPMessage struct {
	Data  []byte
	MsgID uint32
	Proto byte
}

func Parse(buf []byte) (*LDAPMessage, error) {
	msg, _, ok, err := TryParse(buf)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("incomplete message")
	}
	return msg, nil
}

func TryParse(buf []byte) (msg *LDAPMessage, end int, ok bool, err error) {
	if len(buf) < 2 {
		return nil, 0, false, nil
	}
	if buf[0] != ldapTagSequence {
		return nil, 0, false, fmt.Errorf("expected SEQUENCE tag (0x%x) at start of LDAP message", ldapTagSequence)
	}

	size, hdrSize, enough, err := berSizeAt(buf, 1)
	if err != nil {
		return nil, 0, false, err
	}

	if !enough {
		return nil, 0, false, nil
	}

	totalSize := 1 + hdrSize + size
	if len(buf) < totalSize {
		return nil, 0, false, nil
	}

	id, proto, err := messageIdAndProto(buf[:totalSize], 1+hdrSize)
	if err != nil {
		return nil, 0, false, err
	}
	msg = &LDAPMessage{Data: buf[:totalSize], MsgID: id, Proto: proto}
	return msg, totalSize, true, nil
}

func (msg *LDAPMessage) IsDone() bool {
	return msg.Proto == ldapProtoSearchResultDone
}

func messageIdAndProto(buf []byte, offset int) (uint32, byte, error) {
	if offset >= len(buf) || buf[offset] != ldapTagInteger {
		return 0, 0, fmt.Errorf("expected INTEGER tag (0x%x) for messageID", ldapTagInteger)
	}

	idSize, idHdrSize, enough, err := berSizeAt(buf, offset+1)
	if err != nil {
		return 0, 0, err
	}

	if !enough || offset+1+idHdrSize+idSize > len(buf) {
		return 0, 0, errors.New("expected INTEGER value")
	}

	idStart := offset + 1 + idHdrSize
	idBytes := buf[idStart : idStart+idSize]

	if len(idBytes) == 0 {
		return 0, 0, errors.New("empty INTEGER value")
	}
	if idBytes[0]&0x80 != 0 {
		return 0, 0, errors.New("negative messageID")
	}
	if len(idBytes) > 8 {
		return 0, 0, errors.New("messageID too large")
	}
	var id uint64
	for _, b := range idBytes {
		id = (id << 8) | uint64(b)
	}

	if id > 0x7FFF_FFFF {
		return 0, 0, fmt.Errorf("messageID out of range (%d)", id)
	}

	protoOffset := idStart + idSize
	if protoOffset >= len(buf) {
		return 0, 0, errors.New("expected protocolOp tag")
	}

	return uint32(id), buf[protoOffset], nil
}

func berSizeAt(buf []byte, off int) (size, consumed int, ok bool, err error) {
	if off >= len(buf) {
		return 0, 0, false, nil
	}

	b := buf[off]
	if b < 0x80 {
		return int(b), 1, true, nil
	} else if b == 0x80 {
		return 0, 0, false, errors.New("indefinite length")
	}
	n := int(b & 0x7F)
	if n > 8 {
		return 0, 0, false, fmt.Errorf("length-of-length too large (%d)", n)
	}
	if off+1+n > len(buf) {
		return 0, 0, false, nil
	}

	var s uint64
	for i := range n {
		s = (s << 8) | uint64(buf[off+1+i])
	}
	return int(s), 1 + n, true, nil
}
