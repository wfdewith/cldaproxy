package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

type ldapResponse struct {
	msg []byte
	dst *net.UDPAddr
}

type spoofedConnPool struct {
	conns map[netip.AddrPort]*spoofedConn
}

func newSpoofedConnPool() *spoofedConnPool {
	return &spoofedConnPool{conns: make(map[netip.AddrPort]*spoofedConn)}
}

func (p *spoofedConnPool) get(src *net.UDPAddr) (*spoofedConn, error) {
	srcAttr := slog.String("src", src.String())
	conn, ok := p.conns[src.AddrPort()]
	if !ok {
		slog.Debug("creating new socket", srcAttr)
		conn = newSpoofedConn(src)
		err := conn.init()
		if err != nil {
			return nil, err
		}
		p.conns[src.AddrPort()] = conn
		go conn.listen()
	} else {
		slog.Debug("reusing existing socket", srcAttr)
	}
	return conn, nil
}

type spoofedConn struct {
	src  *net.UDPAddr
	ch   chan *ldapResponse
	conn net.PacketConn
}

func newSpoofedConn(src *net.UDPAddr) *spoofedConn {
	return &spoofedConn{src: src, ch: make(chan *ldapResponse)}
}

func (c *spoofedConn) init() error {
	listenConfig := net.ListenConfig{
		Control: func(network, address string, rawConn syscall.RawConn) error {
			var innerErr error
			outerErr := rawConn.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
					innerErr = fmt.Errorf("setsockopt IP_TRANSPARENT: %w", err)
					return
				}
			})
			if innerErr != nil {
				return innerErr
			}
			return outerErr
		},
	}

	var err error
	c.conn, err = listenConfig.ListenPacket(context.Background(), "udp4", c.src.String())
	return err
}

func (c *spoofedConn) listen() {
	srcAttr := slog.String("src", c.src.String())
	for rsp := range c.ch {
		dstAttr := slog.String("dst", rsp.dst.String())

		_, err := c.conn.WriteTo(rsp.msg, rsp.dst)
		if err != nil {
			slog.Warn("failed to send response", srcAttr, dstAttr, slog.String("error", err.Error()))
			continue
		}
	}
}

func (c *spoofedConn) send(rsp *ldapResponse) {
	c.ch <- rsp
}
