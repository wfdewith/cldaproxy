package proxy

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type msgbufs struct {
	buf []byte
	oob []byte
}

type Proxy struct {
	addr    net.UDPAddr
	timeout time.Duration
	pool    sync.Pool
}

func New(ip net.IP, port int) *Proxy {
	return &Proxy{
		addr:    net.UDPAddr{IP: ip, Port: port},
		timeout: 5 * time.Second,
		pool:    sync.Pool{New: func() any { return msgbufs{buf: make([]byte, 65535), oob: make([]byte, 1024)} }},
	}
}

func (p *Proxy) Start() {
	conn, err := net.ListenUDP("udp4", &p.addr)
	if err != nil {
		slog.Error("failed to start proxy", slog.String("error", err.Error()))
		os.Exit(2)
	}
	defer conn.Close()

	for {
		bufs := p.pool.Get().(msgbufs)
		bufn, oobn, flags, src, err := conn.ReadMsgUDP(bufs.buf, bufs.oob)
		if err != nil {
			slog.Warn("failed to read UDP message", slog.String("error", err.Error()))
			p.pool.Put(bufs)
			continue
		}
		go p.processMessage(conn, bufn, oobn, flags, src, bufs)
	}
}

func (p *Proxy) processMessage(udpConn *net.UDPConn, bufn, oobn, flags int, src *net.UDPAddr, bufs msgbufs) {
	defer p.pool.Put(bufs)
	srcAttr := slog.String("src", src.String())

	if flags&syscall.MSG_TRUNC != 0 {
		slog.Warn("data was truncated", srcAttr)
		return
	}
	if flags&syscall.MSG_CTRUNC != 0 {
		slog.Warn("control data was truncated", srcAttr)
		return
	}

	payload := bufs.buf[:bufn]
	oob := bufs.oob[:oobn]

	dst, err := parseOrigDst(oob)
	if err != nil {
		slog.Warn("failed to parse original destination address", srcAttr, slog.String("error", err.Error()))
		return
	}
	dstAttr := slog.String("dst", dst.String())

	deadline := time.Now().Add(p.timeout)
	tcpConn, err := net.DialTimeout("tcp4", dst.String(), p.timeout)
	if err != nil {
		slog.Warn("failed to connect to upstream", srcAttr, dstAttr, slog.String("error", err.Error()))
		return
	}
	defer tcpConn.Close()

	tcpConn.SetDeadline(deadline)
	_, err = tcpConn.Write(payload)
	if err != nil {
		slog.Warn("failed to write message to upstream", srcAttr, dstAttr, slog.String("error", err.Error()))
		return
	}

	var n, total int
	for {
		n, err = tcpConn.Read(bufs.buf[n:])
		if err != nil {
			slog.Warn("failed to read response from upstream", srcAttr, dstAttr, slog.String("error", err.Error()))
			return
		}
		total += n

		msgSize, err := ldapMessageSize(bufs.buf[:total])
		if err != nil {
			slog.Warn("failed to parse response from upstream", srcAttr, dstAttr, slog.String("error", err.Error()))
			return
		}
		if msgSize > uint64(len(bufs.buf)) {
			slog.Warn("LDAP message too large", slog.Uint64("size", msgSize), srcAttr, dstAttr)
			return
		}
		if uint64(n) > msgSize {
			slog.Warn("got more data than expected from upstream", slog.Uint64("expectedSize", msgSize), slog.Int("actualSize", n), srcAttr, dstAttr)
			return
		}
		if uint64(n) == msgSize {
			break
		}
	}

	_, err = udpConn.WriteToUDP(bufs.buf[:total], src)
	if err != nil {
		slog.Warn("failed to send response", srcAttr, dstAttr, slog.String("error", err.Error()))
		return
	}
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

func ldapMessageSize(payload []byte) (uint64, error) {
	if len(payload) < 2 {
		return 0, fmt.Errorf("truncated message, need at least 2 bytes")
	}
	if payload[0] != 0x30 {
		return 0, fmt.Errorf("not a valid ASN.1/BER encoded LDAPMessage")
	}

	b1 := payload[1]
	if b1 < 0x80 {
		return 2 + uint64(b1), nil
	} else if b1 == 0x80 {
		return 0, fmt.Errorf("indefinite length")
	}
	n := int(b1 & 0x7F)
	if n > 8 {
		return 0, fmt.Errorf("length-of-length too large (%d)", n)
	}
	if len(payload) < 2+n {
		return 0, fmt.Errorf("truncated message, need at least %d bytes", 2+n)
	}

	var contentLen uint64
	for i := range n {
		contentLen = (contentLen << 8) | uint64(payload[2+i])
	}
	return uint64(2+n) + contentLen, nil
}
