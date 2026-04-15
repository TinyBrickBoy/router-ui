// bgpd-core — central BGP router daemon.
//
// Responsibilities:
//   1. Manage the WireGuard hub interface and node peers.
//   2. Run an embedded GoBGP speaker that:
//      - Sessions with upstream ISP peers (announce the /24 aggregate).
//      - Sessions with each edge node (accept /26–/27 subnets, inject into FIB).
//   3. Serve the HTTP control-plane API used by agents and bgpctl.
//   4. Run the health checker; mark stale nodes down and withdraw their routes.
//
// Usage:
//   bgpd-core --config /etc/bgpd/core.yaml
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinybrickboy/router-ui/internal/bgp"
	"github.com/tinybrickboy/router-ui/internal/health"
	"github.com/tinybrickboy/router-ui/internal/registry"
	"github.com/tinybrickboy/router-ui/internal/subnet"
	"github.com/tinybrickboy/router-ui/internal/webui"
	"github.com/tinybrickboy/router-ui/internal/wireguard"
	"github.com/tinybrickboy/router-ui/pkg/config"
	"github.com/tinybrickboy/router-ui/web"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	var cfgPath string

	root := &cobra.Command{
		Use:   "bgpd-core",
		Short: "BGP core router daemon",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cfgPath)
		},
	}
	root.Flags().StringVarP(&cfgPath, "config", "c", "/etc/bgpd/core.yaml", "Path to core.yaml")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cfgPath string) error {
	cfg, err := config.LoadCoreConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log := buildLogger(cfg.LogLevel)
	defer func() { _ = log.Sync() }()

	log.Info("bgpd-core starting",
		zap.String("aggregate", cfg.Network.AggregatePrefix),
		zap.Uint32("asn", cfg.BGP.ASN),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── WireGuard ─────────────────────────────────────────────────────────────
	wgPrivKey, err := wireguard.ParseKey(cfg.WireGuard.PrivateKey)
	if err != nil {
		return fmt.Errorf("parse WireGuard private key: %w", err)
	}

	wgMgr, err := wireguard.NewManager(cfg.WireGuard.Interface, log.Named("wg"))
	if err != nil {
		return fmt.Errorf("create WireGuard manager: %w", err)
	}
	defer func() { _ = wgMgr.Close() }()

	if err := wgMgr.Setup(wireguard.InterfaceConfig{
		Name:       cfg.WireGuard.Interface,
		PrivateKey: wgPrivKey,
		ListenPort: cfg.WireGuard.ListenPort,
		Address:    cfg.WireGuard.Address,
		MTU:        cfg.WireGuard.MTU,
	}); err != nil {
		return fmt.Errorf("setup WireGuard interface: %w", err)
	}

	wgPubKey, err := wgMgr.PublicKey()
	if err != nil {
		return fmt.Errorf("get WireGuard public key: %w", err)
	}
	log.Info("WireGuard interface ready",
		zap.String("iface", cfg.WireGuard.Interface),
		zap.String("pubkey", wgPubKey.String()[:8]+"…"),
	)

	// ── BGP speaker ───────────────────────────────────────────────────────────
	listenAddr := cfg.BGP.ListenAddr
	if listenAddr == "" {
		listenAddr = cfg.Network.WGCoreIP
	}

	speaker := bgp.NewSpeaker(bgp.SpeakerConfig{
		ASN:         cfg.BGP.ASN,
		RouterID:    cfg.BGP.RouterID,
		ListenAddr:  listenAddr,
		ListenPort:  cfg.BGP.ListenPort,
		HoldTime:    cfg.BGP.HoldTime,
		Keepalive:   cfg.BGP.Keepalive,
		WGInterface: cfg.WireGuard.Interface,
		// Single-ASN (iBGP): filter FIB injection by WireGuard peer IP range,
		// not by ASN (all nodes share the core's ASN).
		WGPeerRange: cfg.Network.WGPeerRange,
	}, log.Named("bgp"))

	bgpErrCh := make(chan error, 1)
	bgpCtx, bgpCancel := context.WithCancel(ctx)
	defer bgpCancel()

	go func() {
		bgpErrCh <- speaker.Start(bgpCtx)
	}()

	// Give GoBGP a moment to start before configuring policies and peers.
	time.Sleep(200 * time.Millisecond)

	// ── BGP policies ──────────────────────────────────────────────────────────
	pm := bgp.NewPolicyManager(
		speaker.Server(),
		cfg.Network.AggregatePrefix,
		cfg.Network.SubnetBits,
		log.Named("policy"),
	)
	if err := pm.Apply(ctx); err != nil {
		return fmt.Errorf("apply BGP policies: %w", err)
	}

	// ── Upstream ISP peers ────────────────────────────────────────────────────
	for _, up := range cfg.BGP.Upstreams {
		if err := speaker.AddPeer(ctx, up.Address, up.ASN); err != nil {
			log.Warn("Failed to add upstream peer", zap.String("name", up.Name), zap.Error(err))
		}
		if err := bgp.AddUpstreamExportPolicy(ctx, speaker.Server(), up.Address); err != nil {
			log.Warn("Failed to assign export policy to upstream", zap.String("peer", up.Address), zap.Error(err))
		}
	}

	// ── Announce the aggregate /24 ────────────────────────────────────────────
	if err := speaker.AnnounceRoute(ctx, cfg.Network.AggregatePrefix, cfg.Network.WGCoreIP); err != nil {
		return fmt.Errorf("announce aggregate prefix: %w", err)
	}
	log.Info("Aggregate prefix announced", zap.String("prefix", cfg.Network.AggregatePrefix))

	// ── Subnet allocator ──────────────────────────────────────────────────────
	alloc, err := subnet.NewAllocator(cfg.Network.AggregatePrefix, cfg.Network.SubnetBits)
	if err != nil {
		return fmt.Errorf("create subnet allocator: %w", err)
	}

	// ── Node registry + HTTP API ──────────────────────────────────────────────
	reg, err := registry.NewRegistry(
		alloc,
		wgMgr,
		speaker,
		cfg.Network.WGCoreIP,
		wgPubKey.String(),
		"", // core public IP — filled from config if set
		cfg.WireGuard.ListenPort,
		cfg.BGP.ASN,
		cfg.API.APIKey,
		cfg.Network.WGPeerRange,
		registry.Callbacks{
			OnNodeUp: func(nodeID, peerAddr string, peerASN uint32) error {
				log.Info("Node up", zap.String("node_id", nodeID), zap.String("peer", peerAddr))
				return nil
			},
			OnNodeDown: func(nodeID, peerAddr string) error {
				log.Warn("Node down — removing BGP peer", zap.String("node_id", nodeID))
				return speaker.RemovePeer(context.Background(), peerAddr)
			},
		},
		log.Named("registry"),
	)
	if err != nil {
		return fmt.Errorf("create registry: %w", err)
	}

	// ── Health checker ────────────────────────────────────────────────────────
	checker := health.NewChecker(
		&registryAdapter{reg: reg},
		cfg.Health.HeartbeatTimeout,
		cfg.Health.CheckInterval,
		func(nodeID string) {
			log.Warn("Health checker detected node failure", zap.String("node_id", nodeID))
		},
		log.Named("health"),
	)
	go checker.Run(ctx)

	// ── Web UI ────────────────────────────────────────────────────────────────
	ui, err := webui.New(cfg.API.APIKey, web.FS)
	if err != nil {
		return fmt.Errorf("build web UI: %w", err)
	}

	// Mount: API at /api/v1/, dashboard at everything else.
	mux := http.NewServeMux()
	mux.Handle("/api/v1/", reg.Handler())
	mux.Handle("/", ui)

	// ── HTTP server ───────────────────────────────────────────────────────────
	httpSrv := &http.Server{
		Addr:         cfg.API.Listen,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	if cfg.API.TLSCert != "" && cfg.API.TLSKey != "" {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		httpSrv.TLSConfig = tlsCfg
	}

	httpErrCh := make(chan error, 1)
	go func() {
		log.Info("HTTP API listening", zap.String("addr", cfg.API.Listen))
		if cfg.API.TLSCert != "" {
			httpErrCh <- httpSrv.ListenAndServeTLS(cfg.API.TLSCert, cfg.API.TLSKey)
		} else {
			httpErrCh <- httpSrv.ListenAndServe()
		}
	}()

	// ── Signal handling ───────────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Info("Received signal, shutting down", zap.String("signal", sig.String()))
	case err := <-bgpErrCh:
		if err != nil {
			log.Error("BGP server exited with error", zap.Error(err))
		}
	case err := <-httpErrCh:
		if err != nil && err != http.ErrServerClosed {
			log.Error("HTTP server exited with error", zap.Error(err))
		}
	}

	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Warn("HTTP server shutdown error", zap.Error(err))
	}
	log.Info("bgpd-core stopped")
	return nil
}

// ─── Adapter: registry.Registry → health.NodeLister ──────────────────────────

type registryAdapter struct{ reg *registry.Registry }

func (a *registryAdapter) ListNodes() []health.NodeSnapshot {
	nodes := a.reg.ListNodes()
	out := make([]health.NodeSnapshot, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, health.NodeSnapshot{
			ID:            n.ID,
			State:         string(n.State),
			LastHeartbeat: n.LastHeartbeat,
		})
	}
	return out
}

func (a *registryAdapter) MarkDown(nodeID string) { a.reg.MarkDown(nodeID) }

// ─── Logger ───────────────────────────────────────────────────────────────────

func buildLogger(level string) *zap.Logger {
	lvl := zapcore.InfoLevel
	_ = lvl.UnmarshalText([]byte(level))
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	log, _ := cfg.Build()
	return log
}
