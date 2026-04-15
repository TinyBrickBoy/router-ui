// bgpd-agent — edge node daemon.
//
// Startup sequence:
//   1. Load / generate WireGuard keypair.
//   2. Register with the core HTTP API → receive WG config + subnet assignment.
//   3. Configure local WireGuard interface with the core as a peer.
//   4. Start embedded GoBGP session to the core (over WireGuard).
//   5. Announce the assigned subnet with next-hop = own WireGuard IP.
//   6. Send periodic heartbeats to the core.
//
// Usage:
//   bgpd-agent --config /etc/bgpd/node1.yaml
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/tinybrickboy/router-ui/internal/bgp"
	"github.com/tinybrickboy/router-ui/internal/wireguard"
	apitypes "github.com/tinybrickboy/router-ui/pkg/api"
	"github.com/tinybrickboy/router-ui/pkg/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func main() {
	var cfgPath string

	root := &cobra.Command{
		Use:   "bgpd-agent",
		Short: "BGP edge node agent",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cfgPath)
		},
	}
	root.Flags().StringVarP(&cfgPath, "config", "c", "/etc/bgpd/agent.yaml", "Path to agent config")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cfgPath string) error {
	cfg, err := config.LoadAgentConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log := buildLogger(cfg.LogLevel)
	defer func() { _ = log.Sync() }()

	log.Info("bgpd-agent starting",
		zap.String("node_id", cfg.NodeID),
		zap.Uint32("asn", cfg.ASN),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── WireGuard keypair ─────────────────────────────────────────────────────
	var privKey wgtypes.Key
	if cfg.WireGuard.PrivateKey == "" {
		priv, _, err := wireguard.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("generate WireGuard keypair: %w", err)
		}
		privKey = priv
		log.Info("Generated new WireGuard keypair — add private_key to config to persist it",
			zap.String("private_key", privKey.String()),
			zap.String("public_key", privKey.PublicKey().String()),
		)
	} else {
		privKey, err = wireguard.ParseKey(cfg.WireGuard.PrivateKey)
		if err != nil {
			return fmt.Errorf("parse WireGuard private key: %w", err)
		}
	}
	pubKey := privKey.PublicKey()
	log.Info("WireGuard public key", zap.String("pubkey", pubKey.String()[:8]+"…"))

	// ── Register with core ────────────────────────────────────────────────────
	coreAPIBase := fmt.Sprintf("http://%s:%d/api/v1", cfg.Core.PublicIP, cfg.Core.APIPort)
	regResp, err := registerWithRetry(ctx, coreAPIBase, cfg, pubKey, log)
	if err != nil {
		return fmt.Errorf("register with core: %w", err)
	}

	log.Info("Registered successfully",
		zap.String("wg_ip", regResp.WGIP),
		zap.String("subnet", regResp.AssignedSubnet),
		zap.String("bgp_peer", regResp.BGPPeerIP),
	)

	// ── WireGuard interface ───────────────────────────────────────────────────
	wgMgr, err := wireguard.NewManager(cfg.WireGuard.Interface, log.Named("wg"))
	if err != nil {
		return fmt.Errorf("create WireGuard manager: %w", err)
	}
	defer func() { _ = wgMgr.Close() }()

	wgAddr := regResp.WGIP + "/24"
	if err := wgMgr.Setup(wireguard.InterfaceConfig{
		Name:       cfg.WireGuard.Interface,
		PrivateKey: privKey,
		ListenPort: cfg.WireGuard.ListenPort,
		Address:    wgAddr,
		MTU:        cfg.WireGuard.MTU,
	}); err != nil {
		return fmt.Errorf("setup WireGuard interface: %w", err)
	}

	// Add the core as a WireGuard peer.
	corePubKey, err := wgtypes.ParseKey(regResp.CoreWGPublicKey)
	if err != nil {
		return fmt.Errorf("parse core WG public key: %w", err)
	}
	coreWGPeer := wireguard.PeerConfig{
		PublicKey: corePubKey,
		Endpoint: &net.UDPAddr{
			IP:   net.ParseIP(regResp.CorePublicIP),
			Port: regResp.CoreWGPort,
		},
		// Allow BGP management traffic from the core's WG IP.
		AllowedIPs: []net.IPNet{
			{IP: net.ParseIP(regResp.CoreWGIP).To4(), Mask: net.CIDRMask(32, 32)},
		},
	}
	if err := wgMgr.AddPeer(coreWGPeer); err != nil {
		return fmt.Errorf("add core WireGuard peer: %w", err)
	}
	log.Info("WireGuard tunnel configured", zap.String("core_wg_ip", regResp.CoreWGIP))

	// ── BGP speaker ───────────────────────────────────────────────────────────
	speaker := bgp.NewSpeaker(bgp.SpeakerConfig{
		ASN:        cfg.ASN,
		RouterID:   regResp.WGIP,
		ListenAddr: regResp.WGIP,
		ListenPort: 179,
		HoldTime:   cfg.BGP.HoldTime,
		Keepalive:  cfg.BGP.Keepalive,
		// Nodes do not need FIB injection (they're leaf nodes).
		WGInterface: "",
	}, log.Named("bgp"))

	bgpErrCh := make(chan error, 1)
	bgpCtx, bgpCancel := context.WithCancel(ctx)
	defer bgpCancel()

	go func() {
		bgpErrCh <- speaker.Start(bgpCtx)
	}()

	// Allow GoBGP to start.
	time.Sleep(300 * time.Millisecond)

	// Add core as BGP neighbor.
	if err := speaker.AddPeer(ctx, regResp.BGPPeerIP, regResp.BGPPeerASN); err != nil {
		return fmt.Errorf("add BGP peer (core): %w", err)
	}

	// Wait for WireGuard tunnel to be ready before announcing routes.
	log.Info("Waiting for WireGuard tunnel to establish…")
	if err := waitForWGTunnel(ctx, regResp.CoreWGIP, 30*time.Second, log); err != nil {
		log.Warn("WireGuard tunnel check timed out — announcing route anyway", zap.Error(err))
	}

	// Announce the assigned subnet.
	if err := speaker.AnnounceRoute(ctx, regResp.AssignedSubnet, regResp.WGIP); err != nil {
		return fmt.Errorf("announce assigned subnet: %w", err)
	}
	log.Info("Route announced",
		zap.String("prefix", regResp.AssignedSubnet),
		zap.String("next_hop", regResp.WGIP),
	)

	// ── Heartbeat loop ────────────────────────────────────────────────────────
	// Determine heartbeat URL (use WG IP after tunnel is up).
	hbURL := fmt.Sprintf("http://%s:%d/api/v1/nodes/%s/heartbeat",
		regResp.CoreWGIP, cfg.Core.APIPort, cfg.NodeID)
	go heartbeatLoop(ctx, hbURL, cfg, log)

	// ── Signal handling ───────────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Info("Received signal, shutting down", zap.String("signal", sig.String()))
	case err := <-bgpErrCh:
		if err != nil {
			log.Error("BGP speaker exited with error", zap.Error(err))
		}
	}

	// Withdraw route cleanly before exiting.
	withdrawCtx, withdrawCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer withdrawCancel()
	if err := speaker.WithdrawRoute(withdrawCtx, regResp.AssignedSubnet); err != nil {
		log.Warn("Failed to withdraw route on shutdown", zap.Error(err))
	}

	cancel()
	log.Info("bgpd-agent stopped")
	return nil
}

// ─── Registration with retry ──────────────────────────────────────────────────

func registerWithRetry(ctx context.Context, apiBase string, cfg *config.AgentConfig, pubKey wgtypes.Key, log *zap.Logger) (*apitypes.RegisterResponse, error) {
	backoffs := []time.Duration{2, 4, 8, 16, 30}
	url := apiBase + "/nodes/register"

	for attempt, maxAttempts := 0, 10; attempt < maxAttempts; attempt++ {
		resp, err := doRegister(url, cfg, pubKey)
		if err == nil {
			return resp, nil
		}
		wait := backoffs[min(attempt, len(backoffs)-1)] * time.Second
		log.Warn("Registration failed, retrying",
			zap.Error(err),
			zap.Int("attempt", attempt+1),
			zap.Duration("retry_in", wait),
		)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil, fmt.Errorf("failed to register after multiple attempts")
}

func doRegister(url string, cfg *config.AgentConfig, pubKey wgtypes.Key) (*apitypes.RegisterResponse, error) {
	wgPort := cfg.WireGuard.ListenPort
	if wgPort == 0 {
		wgPort = 51820
	}
	body, _ := json.Marshal(apitypes.RegisterRequest{
		NodeID:      cfg.NodeID,
		ASN:         cfg.ASN,
		PublicIP:    cfg.WireGuard.PublicIP,
		WGPort:      wgPort,
		WGPublicKey: pubKey.String(),
	})

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", cfg.Core.APIKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var apiErr apitypes.ErrorResponse
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		return nil, fmt.Errorf("core returned %d: %s", resp.StatusCode, apiErr.Error)
	}

	var regResp apitypes.RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &regResp, nil
}

// ─── Heartbeat loop ───────────────────────────────────────────────────────────

func heartbeatLoop(ctx context.Context, url string, cfg *config.AgentConfig, log *zap.Logger) {
	ticker := time.NewTicker(cfg.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sendHeartbeat(url, cfg); err != nil {
				log.Warn("Heartbeat failed", zap.Error(err))
			}
		}
	}
}

func sendHeartbeat(url string, cfg *config.AgentConfig) error {
	body, _ := json.Marshal(apitypes.HeartbeatRequest{
		NodeID:        cfg.NodeID,
		TimestampUnix: time.Now().Unix(),
		BGPSessionUp:  true, // simplified; could query GoBGP state
		Status:        "healthy",
	})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", cfg.Core.APIKey)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat rejected: HTTP %d", resp.StatusCode)
	}
	return nil
}

// ─── WireGuard tunnel health check ───────────────────────────────────────────

// waitForWGTunnel pings the core's WG IP until it responds or deadline is hit.
func waitForWGTunnel(ctx context.Context, coreWGIP string, timeout time.Duration, log *zap.Logger) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", coreWGIP+":179", 2*time.Second)
		if err == nil {
			conn.Close()
			log.Info("WireGuard tunnel is up (BGP port reachable)")
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return fmt.Errorf("tunnel to %s not reachable after %s", coreWGIP, timeout)
}

// ─── Logger / misc ───────────────────────────────────────────────────────────

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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
