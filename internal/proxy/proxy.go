package proxy

import (
	"log/slog"
	"os"
	"time"

	"github.com/wfdewith/cldaproxy/internal/listener"
	"github.com/wfdewith/cldaproxy/internal/responder"
	"github.com/wfdewith/cldaproxy/internal/session"
)

type Proxy struct {
	port      int
	timeout   time.Duration
	responder *responder.CLDAPResponder
}

func New(port int, timeout time.Duration) *Proxy {
	return &Proxy{
		port:      port,
		timeout:   timeout,
		responder: responder.New(),
	}
}

func (p *Proxy) Start() {
	listener := listener.WithHandler(p.handlePing)

	slog.Info("starting listener", slog.Int("port", p.port))
	err := listener.Listen(p.port)
	if err != nil {
		slog.Error("failed to start listener", slog.String("error", err.Error()))
		os.Exit(2)
	}
}

func (p *Proxy) handlePing(ping *listener.LDAPPing) {
	logger := slog.With(slog.String("src", ping.Src.String()), slog.String("dst", ping.Dst.String()))

	logger.Debug("creating LDAP session with upstream")
	session, err := session.Connect(ping.Dst.AddrPort(), p.timeout)
	if err != nil {
		logger.Warn("failed to create LDAP session", slog.String("error", err.Error()))
		return
	}
	defer session.Close()

	logger.Debug("sending LDAP message to upstream")
	msgs, err := session.SendMessage(ping.Msg)
	if err != nil {
		logger.Warn("failed to send LDAP messages", slog.String("error", err.Error()))
		return
	}

	logger.Debug("sending CLDAP messages back to source")
	err = p.responder.SendMessages(msgs, ping.Dst, ping.Src)
	if err != nil {
		logger.Warn("failed to send CLDAP messages", slog.String("error", err.Error()))
		return
	}
}
