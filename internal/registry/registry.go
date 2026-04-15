// Package registry manages the node state store and exposes the HTTP
// control-plane API consumed by node agents and the bgpctl CLI.
//
// Endpoints:
//   POST   /api/v1/nodes/register          - node registers, gets WG/BGP config
//   POST   /api/v1/nodes/{id}/heartbeat    - periodic liveness ping
//   GET    /api/v1/nodes                   - list all nodes
//   DELETE /api/v1/nodes/{id}             - de-register node (operator only)
//   GET    /api/v1/routes                  - current BGP/kernel route table
//   GET    /api/v1/status                  - operator health summary
//
// All state-mutating requests require the shared API key in the
// "X-API-Key" header.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tinybrickboy/router-ui/internal/bgp"
	"github.com/tinybrickboy/router-ui/internal/subnet"
	"github.com/tinybrickboy/router-ui/internal/wireguard"
	apitypes "github.com/tinybrickboy/router-ui/pkg/api"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Callbacks lets the registry notify external subsystems of node lifecycle
// events without creating circular imports.
type Callbacks struct {
	// OnNodeUp is called when a node registers and its BGP peer is added.
	OnNodeUp func(nodeID, peerAddr string, peerASN uint32) error
	// OnNodeDown is called when a node is de-registered or times out.
	OnNodeDown func(nodeID, peerAddr string) error
}

// Node is the live runtime record of an edge node.
type Node struct {
	// Identity
	ID  string
	ASN uint32

	// Network
	PublicIP    net.IP
	WGPort      int
	WGPublicKey wgtypes.Key
	WGIP        net.IP   // assigned by core
	Subnet      *net.IPNet // assigned subnet

	// State
	State         apitypes.NodeState
	LastHeartbeat time.Time
	BGPSessionUp  bool
}

// Registry stores all registered nodes and handles the HTTP API.
type Registry struct {
	mu        sync.RWMutex
	nodes     map[string]*Node
	callbacks Callbacks

	// Dependencies
	allocator  *subnet.Allocator
	wgMgr      *wireguard.Manager
	bgpSpeaker *bgp.Speaker
	log        *zap.Logger

	// Core identity (sent back to nodes during registration)
	coreWGIP        string
	coreWGPublicKey string
	corePublicIP    string
	coreWGPort      int
	coreASN         uint32
	coreAPIKey      string

	// WireGuard IP counter for assigning IPs to new nodes.
	wgIPPool *wgIPAllocator
}

// NewRegistry constructs a Registry.
func NewRegistry(
	allocator *subnet.Allocator,
	wgMgr *wireguard.Manager,
	bgpSpeaker *bgp.Speaker,
	coreWGIP, coreWGPublicKey, corePublicIP string,
	coreWGPort int,
	coreASN uint32,
	coreAPIKey string,
	wgPeerRange string,
	callbacks Callbacks,
	log *zap.Logger,
) (*Registry, error) {
	pool, err := newWGIPAllocator(wgPeerRange, coreWGIP)
	if err != nil {
		return nil, fmt.Errorf("init WG IP allocator: %w", err)
	}
	return &Registry{
		nodes:           make(map[string]*Node),
		allocator:       allocator,
		wgMgr:           wgMgr,
		bgpSpeaker:      bgpSpeaker,
		log:             log,
		coreWGIP:        coreWGIP,
		coreWGPublicKey: coreWGPublicKey,
		corePublicIP:    corePublicIP,
		coreWGPort:      coreWGPort,
		coreASN:         coreASN,
		coreAPIKey:      coreAPIKey,
		wgIPPool:        pool,
		callbacks:       callbacks,
	}, nil
}

// GetNode returns a copy of the node record, or (nil, false) if not found.
func (r *Registry) GetNode(id string) (*Node, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	n, ok := r.nodes[id]
	if !ok {
		return nil, false
	}
	cp := *n
	return &cp, true
}

// ListNodes returns snapshots of all registered nodes.
func (r *Registry) ListNodes() []*Node {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Node, 0, len(r.nodes))
	for _, n := range r.nodes {
		cp := *n
		out = append(out, &cp)
	}
	return out
}

// MarkDown transitions a node to the down state (called by health checker).
func (r *Registry) MarkDown(nodeID string) {
	r.mu.Lock()
	n, ok := r.nodes[nodeID]
	if !ok {
		r.mu.Unlock()
		return
	}
	if n.State == apitypes.NodeStateDown {
		r.mu.Unlock()
		return
	}
	n.State = apitypes.NodeStateDown
	peerAddr := n.WGIP.String()
	r.mu.Unlock()

	r.log.Warn("Node marked down", zap.String("node_id", nodeID), zap.String("wg_ip", peerAddr))

	if r.callbacks.OnNodeDown != nil {
		if err := r.callbacks.OnNodeDown(nodeID, peerAddr); err != nil {
			r.log.Error("OnNodeDown callback failed", zap.Error(err))
		}
	}
}

// RecordHeartbeat updates last-heartbeat and optionally transitions to active.
func (r *Registry) RecordHeartbeat(nodeID string, bgpUp bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, ok := r.nodes[nodeID]
	if !ok {
		return false
	}
	wasDown := n.State == apitypes.NodeStateDown
	n.LastHeartbeat = time.Now()
	n.BGPSessionUp = bgpUp
	n.State = apitypes.NodeStateActive
	if wasDown {
		r.log.Info("Node recovered", zap.String("node_id", nodeID))
		// Re-add BGP peer asynchronously.
		go func() {
			if r.callbacks.OnNodeUp != nil {
				if err := r.callbacks.OnNodeUp(nodeID, n.WGIP.String(), n.ASN); err != nil {
					r.log.Error("OnNodeUp (recovery) failed", zap.Error(err))
				}
			}
		}()
	}
	return true
}

// ─── HTTP server ──────────────────────────────────────────────────────────────

// ServeHTTP implements http.Handler — mount the registry directly.
func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	path := strings.TrimPrefix(req.URL.Path, "/api/v1")
	switch {
	case req.Method == http.MethodPost && path == "/nodes/register":
		r.handleRegister(w, req)
	case req.Method == http.MethodPost && strings.HasSuffix(path, "/heartbeat"):
		nodeID := strings.TrimSuffix(strings.TrimPrefix(path, "/nodes/"), "/heartbeat")
		r.handleHeartbeat(w, req, nodeID)
	case req.Method == http.MethodGet && path == "/nodes":
		r.handleListNodes(w, req)
	case req.Method == http.MethodDelete && strings.HasPrefix(path, "/nodes/"):
		nodeID := strings.TrimPrefix(path, "/nodes/")
		r.handleDeleteNode(w, req, nodeID)
	case req.Method == http.MethodGet && path == "/routes":
		r.handleListRoutes(w, req)
	case req.Method == http.MethodGet && path == "/status":
		r.handleStatus(w, req)
	default:
		http.NotFound(w, req)
	}
}

// Handler returns an http.Handler rooted at /api/v1/.
func (r *Registry) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/v1/", r)
	return mux
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

func (r *Registry) handleRegister(w http.ResponseWriter, req *http.Request) {
	if !r.checkAPIKey(w, req) {
		return
	}

	var regReq apitypes.RegisterRequest
	if err := json.NewDecoder(req.Body).Decode(&regReq); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if regReq.NodeID == "" || regReq.ASN == 0 || regReq.PublicIP == "" || regReq.WGPublicKey == "" {
		jsonError(w, "missing required fields: node_id, asn, public_ip, wg_public_key", http.StatusBadRequest)
		return
	}

	pubKey, err := wgtypes.ParseKey(regReq.WGPublicKey)
	if err != nil {
		jsonError(w, "invalid wg_public_key: "+err.Error(), http.StatusBadRequest)
		return
	}

	r.mu.Lock()

	// Idempotent: return existing registration if node already registered.
	if existing, ok := r.nodes[regReq.NodeID]; ok {
		resp := r.buildRegisterResponse(existing)
		r.mu.Unlock()
		jsonOK(w, resp)
		return
	}

	// Allocate WireGuard IP.
	wgIP, err := r.wgIPPool.Allocate(regReq.NodeID)
	if err != nil {
		r.mu.Unlock()
		jsonError(w, "WireGuard IP pool exhausted: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Allocate subnet.
	assignedSubnet, err := r.allocator.Allocate(regReq.NodeID)
	if err != nil {
		r.wgIPPool.Release(regReq.NodeID)
		r.mu.Unlock()
		jsonError(w, "subnet pool exhausted: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	node := &Node{
		ID:            regReq.NodeID,
		ASN:           regReq.ASN,
		PublicIP:      net.ParseIP(regReq.PublicIP),
		WGPort:        regReq.WGPort,
		WGPublicKey:   pubKey,
		WGIP:          wgIP,
		Subnet:        assignedSubnet,
		State:         apitypes.NodeStatePending,
		LastHeartbeat: time.Now(),
	}
	r.nodes[regReq.NodeID] = node
	resp := r.buildRegisterResponse(node)
	r.mu.Unlock()

	// Configure WireGuard peer on the core.
	wgPeer := wireguard.PeerConfig{
		PublicKey: pubKey,
		Endpoint: &net.UDPAddr{
			IP:   net.ParseIP(regReq.PublicIP),
			Port: regReq.WGPort,
		},
		AllowedIPs: []net.IPNet{
			{IP: wgIP, Mask: net.CIDRMask(32, 32)},
			*assignedSubnet,
		},
	}
	if err := r.wgMgr.AddPeer(wgPeer); err != nil {
		r.log.Error("Failed to add WireGuard peer", zap.String("node_id", regReq.NodeID), zap.Error(err))
		// Don't fail the registration — WG peer can be re-added on next heartbeat.
	}

	// Add BGP peer (session will establish once WireGuard tunnel is up).
	go func() {
		if err := r.bgpSpeaker.AddPeer(context.Background(), wgIP.String(), regReq.ASN); err != nil {
			r.log.Error("Failed to add BGP peer", zap.String("node_id", regReq.NodeID), zap.Error(err))
		}
		if r.callbacks.OnNodeUp != nil {
			if err := r.callbacks.OnNodeUp(regReq.NodeID, wgIP.String(), regReq.ASN); err != nil {
				r.log.Error("OnNodeUp callback failed", zap.Error(err))
			}
		}
	}()

	r.log.Info("Node registered",
		zap.String("node_id", regReq.NodeID),
		zap.Uint32("asn", regReq.ASN),
		zap.String("wg_ip", wgIP.String()),
		zap.String("subnet", assignedSubnet.String()),
	)
	jsonOK(w, resp)
}

func (r *Registry) handleHeartbeat(w http.ResponseWriter, req *http.Request, nodeID string) {
	if !r.checkAPIKey(w, req) {
		return
	}

	var hbReq apitypes.HeartbeatRequest
	if err := json.NewDecoder(req.Body).Decode(&hbReq); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if !r.RecordHeartbeat(nodeID, hbReq.BGPSessionUp) {
		jsonError(w, fmt.Sprintf("node %q not registered", nodeID), http.StatusNotFound)
		return
	}

	jsonOK(w, apitypes.HeartbeatResponse{Acknowledged: true})
}

func (r *Registry) handleListNodes(w http.ResponseWriter, req *http.Request) {
	if !r.checkAPIKey(w, req) {
		return
	}

	nodes := r.ListNodes()
	infos := make([]apitypes.NodeInfo, 0, len(nodes))
	for _, n := range nodes {
		infos = append(infos, apitypes.NodeInfo{
			NodeID:         n.ID,
			ASN:            n.ASN,
			State:          n.State,
			WGIP:           n.WGIP.String(),
			AssignedSubnet: n.Subnet.String(),
			PublicIP:       n.PublicIP.String(),
			LastHeartbeat:  n.LastHeartbeat,
			BGPSessionUp:   n.BGPSessionUp,
		})
	}
	jsonOK(w, apitypes.ListNodesResponse{Nodes: infos})
}

func (r *Registry) handleDeleteNode(w http.ResponseWriter, req *http.Request, nodeID string) {
	if !r.checkAPIKey(w, req) {
		return
	}

	r.mu.Lock()
	node, ok := r.nodes[nodeID]
	if !ok {
		r.mu.Unlock()
		jsonError(w, fmt.Sprintf("node %q not found", nodeID), http.StatusNotFound)
		return
	}
	wgIP := node.WGIP
	wgKey := node.WGPublicKey
	delete(r.nodes, nodeID)
	r.mu.Unlock()

	// Release subnet.
	if err := r.allocator.Release(nodeID); err != nil {
		r.log.Warn("Failed to release subnet", zap.String("node_id", nodeID), zap.Error(err))
	}
	r.wgIPPool.Release(nodeID)

	// Remove WireGuard peer.
	if err := r.wgMgr.RemovePeer(wgKey); err != nil {
		r.log.Warn("Failed to remove WG peer", zap.String("node_id", nodeID), zap.Error(err))
	}

	// Remove BGP peer (triggers route withdrawal).
	if err := r.bgpSpeaker.RemovePeer(context.Background(), wgIP.String()); err != nil {
		r.log.Warn("Failed to remove BGP peer", zap.String("node_id", nodeID), zap.Error(err))
	}

	if r.callbacks.OnNodeDown != nil {
		_ = r.callbacks.OnNodeDown(nodeID, wgIP.String())
	}

	r.log.Info("Node de-registered", zap.String("node_id", nodeID))
	w.WriteHeader(http.StatusNoContent)
}

func (r *Registry) handleListRoutes(w http.ResponseWriter, req *http.Request) {
	if !r.checkAPIKey(w, req) {
		return
	}

	entries, err := r.bgpSpeaker.ListRIB(context.Background())
	if err != nil {
		jsonError(w, "failed to query RIB: "+err.Error(), http.StatusInternalServerError)
		return
	}

	routes := make([]apitypes.RouteEntry, 0, len(entries))
	for _, e := range entries {
		routes = append(routes, apitypes.RouteEntry{
			Prefix:  e.Prefix,
			NextHop: e.NextHop,
			Source:  apitypes.RouteSourceBGPNode,
			Active:  e.Best,
		})
	}
	jsonOK(w, apitypes.ListRoutesResponse{Routes: routes})
}

func (r *Registry) handleStatus(w http.ResponseWriter, req *http.Request) {
	nodes := r.ListNodes()
	active, down := 0, 0
	for _, n := range nodes {
		switch n.State {
		case apitypes.NodeStateActive:
			active++
		case apitypes.NodeStateDown:
			down++
		}
	}
	jsonOK(w, apitypes.StatusResponse{
		OK:              down == 0,
		Version:         "1.0.0",
		NodesTotal:      len(nodes),
		NodesActive:     active,
		NodesDown:       down,
	})
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func (r *Registry) buildRegisterResponse(n *Node) apitypes.RegisterResponse {
	return apitypes.RegisterResponse{
		WGIP:            n.WGIP.String(),
		AssignedSubnet:  n.Subnet.String(),
		CoreWGIP:        r.coreWGIP,
		CoreWGPublicKey: r.coreWGPublicKey,
		CorePublicIP:    r.corePublicIP,
		CoreWGPort:      r.coreWGPort,
		BGPPeerIP:       r.coreWGIP,
		BGPPeerASN:      r.coreASN,
	}
}

func (r *Registry) checkAPIKey(w http.ResponseWriter, req *http.Request) bool {
	if req.Header.Get("X-API-Key") != r.coreAPIKey {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return false
	}
	return true
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(apitypes.ErrorResponse{Error: msg})
}

// ─── WireGuard IP Allocator ───────────────────────────────────────────────────

// wgIPAllocator assigns WireGuard tunnel IPs from a pool, skipping the core's IP.
type wgIPAllocator struct {
	mu       sync.Mutex
	pool     []net.IP
	assigned map[string]net.IP // nodeID → IP
}

func newWGIPAllocator(cidr, coreIP string) (*wgIPAllocator, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse WG peer range %s: %w", cidr, err)
	}
	core := net.ParseIP(coreIP).To4()

	var pool []net.IP
	for ip := cloneIP(ipNet.IP.To4()); ipNet.Contains(ip); incrementIP(ip) {
		if ip[3] == 0 || ip[3] == 255 {
			continue // skip network/broadcast
		}
		if ip.Equal(core) {
			continue // skip core's own IP
		}
		pool = append(pool, cloneIP(ip))
	}
	return &wgIPAllocator{
		pool:     pool,
		assigned: make(map[string]net.IP),
	}, nil
}

func (a *wgIPAllocator) Allocate(nodeID string) (net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ip, ok := a.assigned[nodeID]; ok {
		return ip, nil
	}
	if len(a.pool) == 0 {
		return nil, fmt.Errorf("WireGuard IP pool exhausted")
	}
	ip := a.pool[0]
	a.pool = a.pool[1:]
	a.assigned[nodeID] = ip
	return ip, nil
}

func (a *wgIPAllocator) Release(nodeID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ip, ok := a.assigned[nodeID]; ok {
		a.pool = append(a.pool, ip)
		delete(a.assigned, nodeID)
	}
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
