package proxy

import (
	"errors"
	"fmt"
)

const LDAP_TAG_SEQUENCE = 0x30
const LDAP_TAG_INTEGER = 0x02
const LDAP_PROTO_SEARCH_RESULT_DONE = 0x65

type ldapMessage struct {
	buf       []byte
	seqOffset int
}

func readLdapMessage(buf []byte) (msg *ldapMessage, end int, ok bool, err error) {
	if len(buf) < 2 {
		return nil, 0, false, nil
	}
	if buf[0] != LDAP_TAG_SEQUENCE {
		return nil, 0, false, fmt.Errorf("expected SEQUENCE tag (0x%x) at start of LDAP message", LDAP_TAG_SEQUENCE)
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

	msg = &ldapMessage{buf: buf[:totalSize], seqOffset: 1 + hdrSize}
	return msg, totalSize, true, nil
}

func (msg *ldapMessage) messageIdAndProto() (uint32, byte, error) {
	if msg.seqOffset >= len(msg.buf) || msg.buf[msg.seqOffset] != LDAP_TAG_INTEGER {
		return 0, 0, fmt.Errorf("expected INTEGER tag (0x%x) for messageID", LDAP_TAG_INTEGER)
	}

	idSize, idHdrSize, enough, err := berSizeAt(msg.buf, msg.seqOffset+1)
	if err != nil {
		return 0, 0, err
	}

	if !enough || msg.seqOffset+1+idHdrSize+idSize > len(msg.buf) {
		return 0, 0, errors.New("expected INTEGER value")
	}

	idStart := msg.seqOffset + 1 + idHdrSize
	idBytes := msg.buf[idStart : idStart+idSize]

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
	if protoOffset >= len(msg.buf) {
		return 0, 0, errors.New("expected protocolOp tag")
	}

	return uint32(id), msg.buf[protoOffset], nil
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
