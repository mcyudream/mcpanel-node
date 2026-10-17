// Package frpc embeds the frp client to establish the outbound TCP tunnel
// used when the node sits behind NAT (protocol §2 controlPlan mode "frp",
// M1b, experimental).
//
// Security rules:
//   - The tunnel relays raw TCP end-to-end to the node TLS listener; it
//     never terminates TLS.
//   - The frp token must be the node-specific proxy credential issued in the
//     controlPlan. The frps admin token must never be configured here.
//   - The client webServer (admin UI) is never started.
package frpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/fatedier/frp/client"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	frpconfigsource "github.com/fatedier/frp/pkg/config/source"
)

// Config is the resolved tunnel configuration (from controlPlan.frp or the
// local development config file).
type Config struct {
	ServerAddr string
	ServerPort int
	User       string // frp proxy user; node-scoped (e.g. node-<nodeId>)
	ProxyName  string // proxy name; unique per ingress allocation
	Token      string // node-specific proxy credential
	RemotePort int    // frps ingress port
	LocalIP    string // node TLS listener address
	LocalPort  int    // node TLS listener port
}

// Validate enforces non-empty credentials and sane targets.
func (c Config) Validate() error {
	if c.ServerAddr == "" || c.ServerPort <= 0 {
		return errors.New("frp serverAddr/serverPort missing")
	}
	if c.Token == "" {
		return errors.New("frp proxy token missing; the frps admin token must not be reused here")
	}
	if c.User == "" {
		return errors.New("frp user missing")
	}
	if c.ProxyName == "" {
		return errors.New("frp proxyName missing")
	}
	if c.RemotePort <= 0 {
		return errors.New("frp remotePort missing")
	}
	if c.LocalIP == "" || c.LocalPort <= 0 {
		return errors.New("frp localIP/localPort must point at the node TLS listener")
	}
	return nil
}

// Runner owns the embedded frpc service lifecycle.
type Runner struct {
	mu     sync.Mutex
	svc    *client.Service
	cancel context.CancelFunc
	log    *slog.Logger
}

// Start launches the embedded frpc. It dials out to the frps and registers
// the proxy; the call returns immediately and the service runs until Stop or
// context cancellation.
func Start(ctx context.Context, cfg Config, log *slog.Logger) (*Runner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}

	common := &v1.ClientCommonConfig{
		User:       cfg.User,
		ServerAddr: cfg.ServerAddr,
		ServerPort: cfg.ServerPort,
		Auth: v1.AuthClientConfig{
			Method: "token",
			Token:  cfg.Token,
		},
	}
	loginFailExit := false
	common.LoginFailExit = &loginFailExit

	proxy := &v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{
			Name: cfg.ProxyName,
			Type: "tcp",
			ProxyBackend: v1.ProxyBackend{
				LocalIP:   cfg.LocalIP,
				LocalPort: cfg.LocalPort,
			},
		},
		RemotePort: cfg.RemotePort,
	}

	aggregator := frpconfigsource.NewAggregator(frpconfigsource.NewConfigSource())
	if err := aggregator.ConfigSource().ReplaceAll([]v1.ProxyConfigurer{proxy}, nil); err != nil {
		return nil, fmt.Errorf("frpc proxy config: %w", err)
	}

	svc, err := client.NewService(client.ServiceOptions{
		Common:                 common,
		ConfigSourceAggregator: aggregator,
	})
	if err != nil {
		return nil, fmt.Errorf("frpc service: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	r := &Runner{svc: svc, cancel: cancel, log: log}
	go func() {
		if err := svc.Run(runCtx); err != nil && runCtx.Err() == nil {
			log.Error("frpc service exited", "err", err)
		}
	}()
	return r, nil
}

// Stop shuts the tunnel down gracefully.
func (r *Runner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		r.cancel()
	}
	if r.svc != nil {
		r.svc.Close()
	}
}
