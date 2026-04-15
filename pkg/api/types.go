// Package api defines the JSON types for the HTTP control-plane between the
// core router and node agents. These mirror the proto definitions in
// proto/bgpd.proto.
package api

import "time"

// ─── Registration ─────────────────────────────────────────────────────────────

// RegisterRequest is sent by a node agent to join the routing fabric.
// With single-ASN (iBGP) deployments the node does not specify its own ASN —
// the core assigns the shared ASN and returns it in RegisterResponse.BGPPeerASN.
type RegisterRequest struct {
	NodeID      string `json:"node_id"`      // unique node name
	PublicIP    string `json:"public_ip"`    // node's public IP (WG endpoint)
	WGPort      int    `json:"wg_port"`      // WireGuard listen port
	WGPublicKey string `json:"wg_public_key"` // base64-encoded WG public key
}

// RegisterResponse is returned by the core after a successful registration.
type RegisterResponse struct {
	// Assigned addressing
	WGIP           string `json:"wg_ip"`            // e.g. "10.100.0.2"
	AssignedSubnet string `json:"assigned_subnet"`  // e.g. "203.0.113.0/26"

	// Core WireGuard peer config
	CoreWGIP        string `json:"core_wg_ip"`         // "10.100.0.1"
	CoreWGPublicKey string `json:"core_wg_public_key"` // base64
	CorePublicIP    string `json:"core_public_ip"`     // core's public IP
	CoreWGPort      int    `json:"core_wg_port"`

	// BGP session info
	BGPPeerIP  string `json:"bgp_peer_ip"`  // = CoreWGIP
	BGPPeerASN uint32 `json:"bgp_peer_asn"` // core's ASN

	Error string `json:"error,omitempty"`
}

// ─── Heartbeat ────────────────────────────────────────────────────────────────

// HeartbeatRequest is sent periodically by the node agent.
type HeartbeatRequest struct {
	NodeID       string `json:"node_id"`
	TimestampUnix int64 `json:"timestamp_unix"`
	BGPSessionUp  bool  `json:"bgp_session_up"`
	Status        string `json:"status"` // "healthy" | "degraded"
}

// HeartbeatResponse confirms receipt.
type HeartbeatResponse struct {
	Acknowledged bool `json:"acknowledged"`
}

// ─── Node list ────────────────────────────────────────────────────────────────

// NodeState represents the lifecycle state of a registered node.
type NodeState string

const (
	NodeStatePending NodeState = "pending" // registered but WG tunnel not yet up
	NodeStateActive  NodeState = "active"  // tunnel + BGP up, routes installed
	NodeStateDown    NodeState = "down"    // heartbeat timed out, routes withdrawn
)

// NodeInfo is a read-only snapshot of a node's runtime state.
type NodeInfo struct {
	NodeID         string    `json:"node_id"`
	ASN            uint32    `json:"asn"`
	State          NodeState `json:"state"`
	WGIP           string    `json:"wg_ip"`
	AssignedSubnet string    `json:"assigned_subnet"`
	PublicIP       string    `json:"public_ip"`
	LastHeartbeat  time.Time `json:"last_heartbeat"`
	BGPSessionUp   bool      `json:"bgp_session_up"`
}

// ListNodesResponse wraps the node list.
type ListNodesResponse struct {
	Nodes []NodeInfo `json:"nodes"`
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// RouteSource identifies where a route came from.
type RouteSource string

const (
	RouteSourceStatic   RouteSource = "static"       // locally originated aggregate
	RouteSourceBGPNode  RouteSource = "bgp-node"     // learned from an edge node
	RouteSourceBGPUpstream RouteSource = "bgp-upstream" // learned from upstream ISP
)

// RouteEntry is a single entry from the core's routing table view.
type RouteEntry struct {
	Prefix  string      `json:"prefix"`
	NextHop string      `json:"next_hop"`
	Source  RouteSource `json:"source"`
	Active  bool        `json:"active"` // false if route exists but is suppressed
}

// ListRoutesResponse wraps the route list.
type ListRoutesResponse struct {
	Routes []RouteEntry `json:"routes"`
}

// ─── Generic ──────────────────────────────────────────────────────────────────

// ErrorResponse is returned on API errors.
type ErrorResponse struct {
	Error string `json:"error"`
}

// StatusResponse is returned by GET /api/v1/status.
type StatusResponse struct {
	OK              bool   `json:"ok"`
	Version         string `json:"version"`
	AggregatePrefix string `json:"aggregate_prefix"`
	BGPUpstreams    int    `json:"bgp_upstreams_configured"`
	NodesTotal      int    `json:"nodes_total"`
	NodesActive     int    `json:"nodes_active"`
	NodesDown       int    `json:"nodes_down"`
}
