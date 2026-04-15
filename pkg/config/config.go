// Package config defines all configuration types used by the core router
// and node agent. Both programs share this package to keep the YAML schema
// consistent. Unmarshalling is done via spf13/viper + mapstructure tags.
package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// ─── Core router ─────────────────────────────────────────────────────────────

// CoreConfig is the top-level configuration for bgpd-core.
type CoreConfig struct {
	BGP       CoreBGPConfig    `mapstructure:"bgp"`
	WireGuard WireGuardConfig  `mapstructure:"wireguard"`
	Network   NetworkConfig    `mapstructure:"network"`
	API       APIConfig        `mapstructure:"api"`
	Health    HealthConfig     `mapstructure:"health"`
	LogLevel  string           `mapstructure:"log_level"`
}

// CoreBGPConfig holds the BGP parameters for the core router.
type CoreBGPConfig struct {
	ASN        uint32      `mapstructure:"asn"`         // e.g. 65000
	RouterID   string      `mapstructure:"router_id"`   // WireGuard IP of core
	ListenAddr string      `mapstructure:"listen_addr"` // bind addr, e.g. "10.100.0.1"
	ListenPort int32       `mapstructure:"listen_port"` // 179
	HoldTime   uint64      `mapstructure:"hold_time"`   // seconds (default 90)
	Keepalive  uint64      `mapstructure:"keepalive"`   // seconds (default 30)
	Upstreams  []BGPUpstream `mapstructure:"upstreams"` // upstream ISP peers
}

// BGPUpstream is an eBGP upstream (transit / route-server).
type BGPUpstream struct {
	Name     string `mapstructure:"name"`
	Address  string `mapstructure:"address"` // peer IP
	ASN      uint32 `mapstructure:"asn"`
	Password string `mapstructure:"password"` // MD5 auth, leave empty to disable
}

// WireGuardConfig configures the WireGuard interface on the core.
type WireGuardConfig struct {
	Interface  string `mapstructure:"interface"`   // e.g. "wg-core"
	ListenPort int    `mapstructure:"listen_port"` // e.g. 51820
	PrivateKey string `mapstructure:"private_key"` // base64 WG private key
	Address    string `mapstructure:"address"`     // IP/prefix on the WG iface, e.g. "10.100.0.1/24"
	MTU        int    `mapstructure:"mtu"`         // 0 → default (1420)
}

// NetworkConfig describes the IP addressing plan.
type NetworkConfig struct {
	// AggregatePrefix is the /24 (or larger) that this ASN owns.
	AggregatePrefix string `mapstructure:"aggregate_prefix"` // e.g. "203.0.113.0/24"

	// SubnetBits is the prefix length used when carving subnets for nodes.
	// 26 → /26 (64 IPs each), 27 → /27 (32 IPs each).
	SubnetBits int `mapstructure:"subnet_bits"` // 26 or 27

	// WGPeerRange is the WireGuard management IP range (NOT routed publicly).
	WGPeerRange string `mapstructure:"wg_peer_range"` // e.g. "10.100.0.0/24"

	// WGCoreIP is the core router's WireGuard IP (must be in WGPeerRange).
	WGCoreIP string `mapstructure:"wg_core_ip"` // e.g. "10.100.0.1"
}

// APIConfig controls the HTTP control-plane server.
type APIConfig struct {
	Listen  string `mapstructure:"listen"`   // e.g. "0.0.0.0:8080"
	TLSCert string `mapstructure:"tls_cert"` // PEM file path (optional)
	TLSKey  string `mapstructure:"tls_key"`  // PEM file path (optional)
	APIKey  string `mapstructure:"api_key"`  // shared secret for node auth
}

// HealthConfig controls failure-detection timing.
type HealthConfig struct {
	// HeartbeatTimeout is how long a node may be silent before marked down.
	HeartbeatTimeout time.Duration `mapstructure:"heartbeat_timeout"` // e.g. "90s"
	// CheckInterval is how often the health goroutine sweeps the node list.
	CheckInterval time.Duration `mapstructure:"check_interval"` // e.g. "15s"
}

// LoadCoreConfig reads and validates a core configuration file.
func LoadCoreConfig(path string) (*CoreConfig, error) {
	v := viper.New()
	v.SetConfigFile(path)
	setCoreDefs(v)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read core config %s: %w", path, err)
	}
	var cfg CoreConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal core config: %w", err)
	}
	return &cfg, validateCoreConfig(&cfg)
}

func setCoreDefs(v *viper.Viper) {
	v.SetDefault("log_level", "info")
	v.SetDefault("bgp.listen_port", 179)
	v.SetDefault("bgp.hold_time", 90)
	v.SetDefault("bgp.keepalive", 30)
	v.SetDefault("network.subnet_bits", 26)
	v.SetDefault("api.listen", "0.0.0.0:8080")
	v.SetDefault("wireguard.interface", "wg-core")
	v.SetDefault("wireguard.listen_port", 51820)
	v.SetDefault("wireguard.mtu", 1420)
	v.SetDefault("health.heartbeat_timeout", "90s")
	v.SetDefault("health.check_interval", "15s")
}

func validateCoreConfig(c *CoreConfig) error {
	if c.BGP.ASN == 0 {
		return fmt.Errorf("bgp.asn must be set")
	}
	if c.BGP.RouterID == "" {
		return fmt.Errorf("bgp.router_id must be set")
	}
	if c.WireGuard.PrivateKey == "" {
		return fmt.Errorf("wireguard.private_key must be set")
	}
	if c.WireGuard.Address == "" {
		return fmt.Errorf("wireguard.address must be set")
	}
	if c.Network.AggregatePrefix == "" {
		return fmt.Errorf("network.aggregate_prefix must be set")
	}
	if c.API.APIKey == "" {
		return fmt.Errorf("api.api_key must be set")
	}
	return nil
}

// ─── Node agent ──────────────────────────────────────────────────────────────

// AgentConfig is the top-level configuration for bgpd-agent.
// With single-ASN iBGP, the ASN is returned by the core during registration
// and does NOT need to be set here.
type AgentConfig struct {
	NodeID            string               `mapstructure:"node_id"`
	Core              CoreConnectionConfig `mapstructure:"core"`
	WireGuard         AgentWGConfig        `mapstructure:"wireguard"`
	BGP               AgentBGPConfig       `mapstructure:"bgp"`
	HeartbeatInterval time.Duration        `mapstructure:"heartbeat_interval"`
	LogLevel          string               `mapstructure:"log_level"`
}

// CoreConnectionConfig tells the agent how to reach the core control-plane.
type CoreConnectionConfig struct {
	PublicIP string `mapstructure:"public_ip"` // core's public IP for initial registration
	APIPort  int    `mapstructure:"api_port"`  // e.g. 8080
	APIKey   string `mapstructure:"api_key"`   // must match core's api.api_key
}

// AgentWGConfig is the WireGuard configuration on the node.
type AgentWGConfig struct {
	Interface  string `mapstructure:"interface"`   // e.g. "wg0"
	PrivateKey string `mapstructure:"private_key"` // base64; generated on first run if empty
	ListenPort int    `mapstructure:"listen_port"` // e.g. 51820
	PublicIP   string `mapstructure:"public_ip"`   // this node's public IP (for WG endpoint)
	MTU        int    `mapstructure:"mtu"`
}

// AgentBGPConfig controls the agent's BGP session.
type AgentBGPConfig struct {
	HoldTime  uint64 `mapstructure:"hold_time"`
	Keepalive uint64 `mapstructure:"keepalive"`
}

// LoadAgentConfig reads and validates a node agent configuration file.
func LoadAgentConfig(path string) (*AgentConfig, error) {
	v := viper.New()
	v.SetConfigFile(path)
	setAgentDefs(v)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read agent config %s: %w", path, err)
	}
	var cfg AgentConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal agent config: %w", err)
	}
	return &cfg, validateAgentConfig(&cfg)
}

func setAgentDefs(v *viper.Viper) {
	v.SetDefault("log_level", "info")
	v.SetDefault("bgp.hold_time", 90)
	v.SetDefault("bgp.keepalive", 30)
	v.SetDefault("wireguard.interface", "wg0")
	v.SetDefault("wireguard.listen_port", 51820)
	v.SetDefault("wireguard.mtu", 1420)
	v.SetDefault("core.api_port", 8080)
	v.SetDefault("heartbeat_interval", "30s")
}

func validateAgentConfig(c *AgentConfig) error {
	if c.NodeID == "" {
		return fmt.Errorf("node_id must be set")
	}
	if c.Core.PublicIP == "" {
		return fmt.Errorf("core.public_ip must be set")
	}
	if c.Core.APIKey == "" {
		return fmt.Errorf("core.api_key must be set")
	}
	if c.WireGuard.PublicIP == "" {
		return fmt.Errorf("wireguard.public_ip must be set (this node's public IP)")
	}
	return nil
}
