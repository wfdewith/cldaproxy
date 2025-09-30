package session

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/wfdewith/cldaproxy/internal/parser"
)

type LDAPSession struct {
	conn net.Conn
}

func Connect(upstream netip.AddrPort, timeout time.Duration) (*LDAPSession, error) {
	deadline := time.Now().Add(timeout)

	conn, err := net.DialTimeout("tcp4", upstream.String(), timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(deadline)
	return &LDAPSession{conn: conn}, nil
}

func (s *LDAPSession) SendMessage(msg *parser.LDAPMessage) ([]*parser.LDAPMessage, error) {
	_, err := s.conn.Write(msg.Data)
	if err != nil {
		return nil, err
	}
	return s.waitForResponse(msg.MsgID)
}

func (s *LDAPSession) waitForResponse(reqMsgID uint32) ([]*parser.LDAPMessage, error) {
	var msgs []*parser.LDAPMessage

	buf := make([]byte, 65535)

	var parseStart, bytesRead, totalBytesRead int
	for {
		msg, offset, ok, err := parser.TryParse(buf[parseStart:totalBytesRead])
		if err != nil {
			return nil, fmt.Errorf("failed to parse LDAP message from upstream: %w", err)
		}
		if ok {
			if reqMsgID != msg.MsgID {
				return nil, fmt.Errorf("upstream response messageID (%d) does not match request messageID (%d)", msg.MsgID, reqMsgID)
			}
			msgs = append(msgs, msg)
			if msg.IsDone() {
				break
			}
			parseStart = offset
			continue
		}

		bytesRead, err = s.conn.Read(buf[totalBytesRead:])
		totalBytesRead += bytesRead
		if err != nil {
			return nil, err
		}
	}
	return msgs, nil
}

func (s *LDAPSession) Close() {
	s.conn.Close()
}
