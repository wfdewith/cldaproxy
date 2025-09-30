package responder

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/wfdewith/cldaproxy/internal/parser"
	"golang.org/x/sys/unix"
)

type CLDAPResponder struct {
	conns map[netip.AddrPort]*responderConn
	mtx   sync.RWMutex
}

func New() *CLDAPResponder {
	return &CLDAPResponder{conns: make(map[netip.AddrPort]*responderConn)}
}

func (cr *CLDAPResponder) SendMessages(msgs []*parser.LDAPMessage, src, dst *net.UDPAddr) error {
	conn, err := cr.connFor(src)
	if err != nil {
		return err
	}
	conn.send(&cldapResponse{msgs: msgs, dst: dst})
	return nil
}

func (cr *CLDAPResponder) connFor(src *net.UDPAddr) (conn *responderConn, err error) {
	logger := slog.With(slog.String("src", src.String()))

	cr.mtx.RLock()
	conn, ok := cr.conns[src.AddrPort()]
	cr.mtx.RUnlock()

	if !ok {
		cr.mtx.Lock()
		// We must check again if the connection is created because it may be
		// created between unlocking the read lock and locking the write lock.
		conn, ok = cr.conns[src.AddrPort()]
		if !ok {
			logger.Debug("creating new socket")
			conn, err = createResponderConn(src)
			if err != nil {
				cr.mtx.Unlock()
				return nil, err
			}
			cr.conns[src.AddrPort()] = conn
			cr.mtx.Unlock()
			go conn.listen()
		}
	} else {
		logger.Debug("reusing existing socket")
	}
	return conn, nil
}

type cldapResponse struct {
	msgs []*parser.LDAPMessage
	dst  *net.UDPAddr
}

type responderConn struct {
	src  *net.UDPAddr
	ch   chan *cldapResponse
	conn net.PacketConn
}

func createResponderConn(src *net.UDPAddr) (rc *responderConn, err error) {
	rc = &responderConn{src: src, ch: make(chan *cldapResponse)}

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

	rc.conn, err = listenConfig.ListenPacket(context.Background(), "udp4", src.String())
	return
}

func (rc *responderConn) listen() {
	logger := slog.With(slog.String("src", rc.src.String()))

	var buf bytes.Buffer
	for rsp := range rc.ch {
		logger = slog.With(slog.String("dst", rsp.dst.String()))

		buf.Truncate(0)
		for _, msg := range rsp.msgs {
			buf.Write(msg.Data)
		}

		_, err := rc.conn.WriteTo(buf.Bytes(), rsp.dst)
		if err != nil {
			logger.Warn("failed to send response", slog.String("error", err.Error()))
			continue
		}
	}
}

func (rc *responderConn) send(rsp *cldapResponse) {
	rc.ch <- rsp
}
