// Package wireguard manages WireGuard interfaces and peers using the kernel
// netlink API (for interface/address lifecycle) and wgctrl (for cryptographic
// configuration). Requires CAP_NET_ADMIN or root.
package wireguard

import (
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const defaultKeepalive = 25 * time.Second

// InterfaceConfig holds all settings needed to bring up a WireGuard interface.
type InterfaceConfig struct {
	Name       string         // e.g. "wg-core" or "wg0"
	PrivateKey wgtypes.Key    // private key
	ListenPort int            // UDP listen port
	Address    string         // IP/mask for the interface, e.g. "10.100.0.1/24"
	MTU        int            // 0 → leave at kernel default (1420 recommended for WG)
}

// PeerConfig describes a remote WireGuard peer to be added.
type PeerConfig struct {
	PublicKey           wgtypes.Key
	Endpoint            *net.UDPAddr // nil = passive (wait for peer to connect)
	AllowedIPs          []net.IPNet  // cryptokey routing entries
	PersistentKeepalive time.Duration // 0 → use defaultKeepalive
}

// Manager owns the lifecycle of a single WireGuard interface.
type Manager struct {
	name   string
	client *wgctrl.Client
	log    *zap.Logger
}

// NewManager creates a Manager and opens a wgctrl client.
// Call Setup to actually create the interface.
func NewManager(ifaceName string, log *zap.Logger) (*Manager, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("open wgctrl client: %w", err)
	}
	return &Manager{name: ifaceName, client: c, log: log}, nil
}

// Setup creates (or re-configures) the WireGuard interface described by cfg.
// It is idempotent: if the interface already exists it will be reconfigured.
func (m *Manager) Setup(cfg InterfaceConfig) error {
	if err := m.ensureInterface(cfg.Name, cfg.MTU); err != nil {
		return err
	}

	port := cfg.ListenPort
	wgCfg := wgtypes.Config{
		PrivateKey:   &cfg.PrivateKey,
		ListenPort:   &port,
		ReplacePeers: false, // preserve existing peers
	}
	if err := m.client.ConfigureDevice(cfg.Name, wgCfg); err != nil {
		return fmt.Errorf("configure wg device %s: %w", cfg.Name, err)
	}

	// Assign IP address.
	addr, err := netlink.ParseAddr(cfg.Address)
	if err != nil {
		return fmt.Errorf("parse wg address %s: %w", cfg.Address, err)
	}
	link, err := netlink.LinkByName(cfg.Name)
	if err != nil {
		return fmt.Errorf("find link %s: %w", cfg.Name, err)
	}
	// AddrReplace is idempotent.
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("assign address %s to %s: %w", cfg.Address, cfg.Name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("set link %s up: %w", cfg.Name, err)
	}

	m.log.Info("WireGuard interface configured",
		zap.String("iface", cfg.Name),
		zap.String("address", cfg.Address),
		zap.Int("port", cfg.ListenPort),
	)
	return nil
}

// AddPeer adds or replaces a WireGuard peer.
// The peer is identified by its public key (immutable per WireGuard spec).
func (m *Manager) AddPeer(peer PeerConfig) error {
	ka := defaultKeepalive
	if peer.PersistentKeepalive > 0 {
		ka = peer.PersistentKeepalive
	}

	peerCfg := wgtypes.PeerConfig{
		PublicKey:                   peer.PublicKey,
		ReplaceAllowedIPs:           true,
		AllowedIPs:                  peer.AllowedIPs,
		PersistentKeepaliveInterval: &ka,
	}
	if peer.Endpoint != nil {
		peerCfg.Endpoint = peer.Endpoint
	}

	if err := m.client.ConfigureDevice(m.name, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerCfg},
	}); err != nil {
		return fmt.Errorf("add peer %s to %s: %w", peer.PublicKey, m.name, err)
	}

	m.log.Info("WireGuard peer added",
		zap.String("iface", m.name),
		zap.String("peer_pubkey", peer.PublicKey.String()[:8]+"…"),
		zap.Any("allowed_ips", allowedIPStrings(peer.AllowedIPs)),
	)
	return nil
}

// RemovePeer removes the peer identified by publicKey.
func (m *Manager) RemovePeer(publicKey wgtypes.Key) error {
	if err := m.client.ConfigureDevice(m.name, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{PublicKey: publicKey, Remove: true},
		},
	}); err != nil {
		return fmt.Errorf("remove peer %s from %s: %w", publicKey, m.name, err)
	}
	m.log.Info("WireGuard peer removed",
		zap.String("iface", m.name),
		zap.String("peer_pubkey", publicKey.String()[:8]+"…"),
	)
	return nil
}

// Device returns a snapshot of the WireGuard interface state.
func (m *Manager) Device() (*wgtypes.Device, error) {
	return m.client.Device(m.name)
}

// PublicKey returns the public key of the managed interface.
func (m *Manager) PublicKey() (wgtypes.Key, error) {
	dev, err := m.client.Device(m.name)
	if err != nil {
		return wgtypes.Key{}, err
	}
	return dev.PublicKey, nil
}

// Teardown removes the WireGuard interface from the kernel.
func (m *Manager) Teardown() error {
	link, err := netlink.LinkByName(m.name)
	if err != nil {
		// Interface already gone — not an error.
		return nil
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("delete link %s: %w", m.name, err)
	}
	return nil
}

// Close releases the wgctrl client handle.
func (m *Manager) Close() error {
	return m.client.Close()
}

// ─── Key helpers ──────────────────────────────────────────────────────────────

// GenerateKeyPair creates a new WireGuard private key and derives the public key.
func GenerateKeyPair() (private wgtypes.Key, public wgtypes.Key, err error) {
	private, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		return
	}
	public = private.PublicKey()
	return
}

// ParseKey parses a base64-encoded WireGuard key (private or public).
func ParseKey(b64 string) (wgtypes.Key, error) {
	return wgtypes.ParseKey(b64)
}

// ─── Kernel route helpers ─────────────────────────────────────────────────────

// InstallRoute adds (or replaces) a kernel route via the WireGuard interface.
// nextHop must be reachable through the WireGuard peer's allowed-ips.
func InstallRoute(ifaceName string, dst *net.IPNet, nextHop net.IP) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("find link %s: %w", ifaceName, err)
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Gw:        nextHop,
		Protocol:  netlink.RouteProtocol(186), // 186 = BGP (by convention)
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("install route %s via %s on %s: %w", dst, nextHop, ifaceName, err)
	}
	return nil
}

// RemoveRoute deletes a kernel route for dst.
func RemoveRoute(dst *net.IPNet) error {
	route := &netlink.Route{Dst: dst}
	if err := netlink.RouteDel(route); err != nil {
		return fmt.Errorf("remove route %s: %w", dst, err)
	}
	return nil
}

// AddBlackholeRoute installs a blackhole (null route) for dst.
// Used to prevent traffic loops when all nodes serving a subnet are down.
func AddBlackholeRoute(dst *net.IPNet) error {
	route := &netlink.Route{
		Dst:  dst,
		Type: 6, // RTN_BLACKHOLE
	}
	return netlink.RouteReplace(route)
}

// RemoveBlackholeRoute removes a previously installed blackhole route.
func RemoveBlackholeRoute(dst *net.IPNet) error {
	return RemoveRoute(dst)
}

// ─── Internal ─────────────────────────────────────────────────────────────────

func (m *Manager) ensureInterface(name string, mtu int) error {
	// Check if the interface already exists.
	if _, err := netlink.LinkByName(name); err == nil {
		m.log.Debug("WireGuard interface already exists", zap.String("iface", name))
		return nil
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	if mtu > 0 {
		attrs.MTU = mtu
	}
	wgLink := &netlink.GenericLink{
		LinkAttrs: attrs,
		LinkType:  "wireguard",
	}
	if err := netlink.LinkAdd(wgLink); err != nil {
		return fmt.Errorf("create wireguard interface %s: %w", name, err)
	}
	m.log.Info("Created WireGuard interface", zap.String("iface", name))
	return nil
}

func allowedIPStrings(ips []net.IPNet) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}
