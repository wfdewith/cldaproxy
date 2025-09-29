package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Proxy struct {
	addr     net.UDPAddr
	timeout  time.Duration
	connPool *spoofedConnPool
}

func New(port int, timeout time.Duration) *Proxy {
	return &Proxy{
		addr:     net.UDPAddr{IP: net.IPv4zero, Port: port},
		timeout:  timeout,
		connPool: newSpoofedConnPool(),
	}
}

func (p *Proxy) Start() {
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

	slog.Info("starting proxy", slog.String("listen", p.addr.String()))
	pConn, err := listenConfig.ListenPacket(context.Background(), "udp4", p.addr.String())
	if err != nil {
		slog.Error("failed to start proxy", slog.String("error", err.Error()))
		os.Exit(2)
	}
	conn := pConn.(*net.UDPConn)
	defer conn.Close()

	for {
		buf := make([]byte, 65536)
		oob := make([]byte, 1024)
		bufn, oobn, flags, src, err := conn.ReadMsgUDP(buf, oob)
		if err != nil {
			slog.Warn("failed to read UDP message", slog.String("error", err.Error()))
			continue
		}

		srcAttr := slog.String("src", src.String())

		slog.Debug("received message", srcAttr)
		if flags&syscall.MSG_TRUNC != 0 {
			slog.Warn("data was truncated", srcAttr)
			return
		}
		if flags&syscall.MSG_CTRUNC != 0 {
			slog.Warn("control data was truncated", srcAttr)
			return
		}

		go p.processMessage(buf[:bufn], oob[:oobn], buf, src)
	}
}

func (p *Proxy) processMessage(buf, oob, fullBuf []byte, src *net.UDPAddr) {
	srcAttr := slog.String("src", src.String())

	dst, err := parseOrigDst(oob)
	if err != nil {
		slog.Warn("failed to parse original destination address", srcAttr, slog.String("error", err.Error()))
		return
	}
	dstAttr := slog.String("dst", dst.String())

	reqMsg, _, ok, err := readLdapMessage(buf)
	if !ok {
		err = errors.New("incomplete message")
	}
	if err != nil {
		slog.Warn("failed to parse message", srcAttr, slog.String("error", err.Error()))
		return
	}
	reqID, _, err := reqMsg.messageIdAndProto()
	if err != nil {
		slog.Warn("failed to parse message", srcAttr, slog.String("error", err.Error()))
		return
	}

	slog.Debug("connecting to upstream", srcAttr, dstAttr)
	deadline := time.Now().Add(p.timeout)
	tcpConn, err := net.DialTimeout("tcp4", dst.String(), p.timeout)
	if err != nil {
		slog.Warn("failed to connect to upstream", srcAttr, dstAttr, slog.String("error", err.Error()))
		return
	}
	defer tcpConn.Close()

	slog.Debug("sending original message to upstream", srcAttr, dstAttr)
	tcpConn.SetDeadline(deadline)
	_, err = tcpConn.Write(buf)
	if err != nil {
		slog.Warn("failed to write message to upstream", srcAttr, dstAttr, slog.String("error", err.Error()))
		return
	}

	slog.Debug("receiving response message from upstream", srcAttr, dstAttr)
	var msgStart, n, total int
	for {
		msg, off, ok, err := readLdapMessage(fullBuf[msgStart:total])
		if err != nil {
			slog.Warn("failed to parse response from upstream", srcAttr, dstAttr, slog.String("error", err.Error()))
			return
		}
		if ok {
			id, proto, err := msg.messageIdAndProto()
			if err != nil {
				slog.Warn("failed to parse response from upstream", srcAttr, dstAttr, slog.String("error", err.Error()))
				return
			}
			if id != reqID {
				reqIDAttr := slog.Int("reqID", int(reqID))
				rspIDAttr := slog.Int("rspID", int(id))
				slog.Warn("upstream response messageID does not match request", srcAttr, dstAttr, reqIDAttr, rspIDAttr)
				return
			}
			if proto == LDAP_PROTO_SEARCH_RESULT_DONE {
				break
			}
			msgStart = off
			continue
		}

		n, err = tcpConn.Read(fullBuf[total:])
		total += n
		if err != nil {
			slog.Warn("failed to read response from upstream", srcAttr, dstAttr, slog.String("error", err.Error()))
			return
		}
	}

	slog.Debug("sending response message to client", srcAttr, dstAttr)
	rsp := &ldapResponse{msg: fullBuf[:total], dst: src}
	spoofedConn, err := p.connPool.get(dst)
	if err != nil {
		slog.Warn("failed to send response", srcAttr, dstAttr, slog.String("error", err.Error()))
		return
	}
	spoofedConn.send(rsp)
}

func parseOrigDst(oob []byte) (*net.UDPAddr, error) {
	cmsgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("ParseSocketControlMessage: %w", err)
	}
	for _, c := range cmsgs {
		if c.Header.Level == unix.SOL_IP && c.Header.Type == unix.IP_RECVORIGDSTADDR {
			// struct sockaddr_in
			// [0:2] sin_family
			// [2:4] sin_port (big-endian)
			// [4:8] sin_addr
			if len(c.Data) < 8 {
				return nil, fmt.Errorf("short ORIGDSTADDR cmsg (%d bytes)", len(c.Data))
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
	return nil, fmt.Errorf("ORIGDSTADDR not found in control data")
}
