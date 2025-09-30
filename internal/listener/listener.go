package listener

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"syscall"

	"github.com/wfdewith/cldaproxy/internal/parser"
	"golang.org/x/sys/unix"
)

type LDAPPing struct {
	Msg *parser.LDAPMessage
	Src *net.UDPAddr
	Dst *net.UDPAddr
}

type HandlePing func(*LDAPPing)

type CLDAPListener struct {
	handler HandlePing
}

func WithHandler(handler HandlePing) *CLDAPListener {
	return &CLDAPListener{handler: handler}
}

func (l *CLDAPListener) Listen(port int) error {
	listenConfig := net.ListenConfig{
		Control: func(network, address string, rawConn syscall.RawConn) error {
			var innerErr error
			outerErr := rawConn.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
					innerErr = fmt.Errorf("setsockopt IP_TRANSPARENT: %w", err)
					return
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
					innerErr = fmt.Errorf("setsockopt IP_RECVORIGDSTADDR: %w", err)
					return
				}
			})
			if innerErr != nil {
				return innerErr
			}
			return outerErr
		},
	}

	pConn, err := listenConfig.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return err
	}

	conn := pConn.(*net.UDPConn)
	defer conn.Close()

	buf := make([]byte, 65535)
	oob := make([]byte, 2048)
	for {
		bufn, oobn, flags, src, err := conn.ReadMsgUDP(buf, oob)
		if err != nil {
			slog.Warn("failed to read UDP message", slog.String("error", err.Error()))
			continue
		}

		logger := slog.With(slog.String("src", src.String()))

		logger.Debug("received message")
		if flags&syscall.MSG_TRUNC != 0 {
			logger.Warn("data was truncated")
			continue
		}
		if flags&syscall.MSG_CTRUNC != 0 {
			logger.Warn("control data was truncated")
			continue
		}

		newBuf := append([]byte(nil), buf[:bufn]...)
		newOob := append([]byte(nil), oob[:oobn]...)

		go l.process(newBuf, newOob, src)
	}
}

func (l *CLDAPListener) process(buf, oob []byte, src *net.UDPAddr) {
	logger := slog.With(slog.String("src", src.String()))

	logger.Debug("parsing original destination")
	dst, err := parseOrigDst(oob)
	if err != nil {
		logger.Warn("failed to parse original destination address", slog.String("error", err.Error()))
		return
	}

	logger = logger.With(slog.String("dst", dst.String()))

	logger.Debug("parsing LDAP message")
	msg, err := parser.Parse(buf)
	if err != nil {
		logger.Warn("failed to parse LDAP message", slog.String("error", err.Error()))
		return
	}

	ping := &LDAPPing{Msg: msg, Src: src, Dst: dst}
	l.handler(ping)
}

func parseOrigDst(oob []byte) (*net.UDPAddr, error) {
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("failed to parse socket control message: %w", err)
	}
	for _, c := range cmsgs {
		if c.Header.Level == unix.SOL_IP && c.Header.Type == unix.IP_RECVORIGDSTADDR {
			// struct sockaddr_in
			// [0:2] sin_family
			// [2:4] sin_port (big-endian)
			// [4:8] sin_addr
			if len(c.Data) < 8 {
				return nil, fmt.Errorf("truncated ORIGDSTADDR socket control message (%d bytes)", len(c.Data))
			}
			family := int(binary.LittleEndian.Uint16(c.Data[0:2]))
			if family != unix.AF_INET {
				return nil, fmt.Errorf("ORIGDSTADDR is not IPv4")
			}
			port := int(binary.BigEndian.Uint16(c.Data[2:4]))
			ip := net.IPv4(c.Data[4], c.Data[5], c.Data[6], c.Data[7])
			return &net.UDPAddr{IP: ip, Port: port}, nil
		}
	}
	return nil, fmt.Errorf("ORIGDSTADDR not found in socket control messages")
}
