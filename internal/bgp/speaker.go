// Package bgp wraps the embedded GoBGP server and provides a clean domain API
// for announcing/withdrawing routes, managing peers, and injecting learned
// routes into the kernel FIB via netlink.
package bgp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/anypb"
)

// SpeakerConfig configures the embedded BGP speaker.
type SpeakerConfig struct {
	ASN        uint32
	RouterID   string // must be a valid IPv4 address string
	ListenAddr string // bind address for BGP sessions
	ListenPort int32  // 179 for production

	// HoldTime / Keepalive for all sessions (seconds).
	HoldTime  uint64
	Keepalive uint64

	// WGInterface is the WireGuard interface name used for kernel FIB injection.
	// Set to "" to disable automatic FIB management.
	WGInterface string

	// NodeASNRange, if set, limits kernel-route injection to paths whose
	// AS-PATH origin falls within [Min, Max]. Paths from outside this range
	// (e.g. upstream transit routes) are not injected.
	NodeASNRange *ASNRange
}

// ASNRange is an inclusive range of private ASNs assigned to edge nodes.
type ASNRange struct {
	Min, Max uint32
}

// Contains reports whether asn is in the range.
func (r *ASNRange) Contains(asn uint32) bool {
	return asn >= r.Min && asn <= r.Max
}

// Speaker embeds a GoBGP server and exposes a simplified routing API.
type Speaker struct {
	cfg    SpeakerConfig
	server *server.BgpServer
	log    *zap.Logger

	mu        sync.Mutex
	pathUUIDs map[string][]byte // prefix-string → GoBGP path UUID
}

// NewSpeaker creates a Speaker but does not start it. Call Start(ctx).
func NewSpeaker(cfg SpeakerConfig, log *zap.Logger) *Speaker {
	return &Speaker{
		cfg:       cfg,
		log:       log,
		pathUUIDs: make(map[string][]byte),
	}
}

// Start launches the embedded GoBGP server and begins the best-path watcher.
// It blocks until ctx is cancelled, so call it in a goroutine.
func (s *Speaker) Start(ctx context.Context) error {
	opts := []server.ServerOption{
		server.LoggerOption(&zapLogger{s.log.Named("gobgp")}),
	}
	s.server = server.NewBgpServer(opts...)
	go s.server.Serve()

	if err := s.server.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:             s.cfg.ASN,
			RouterId:        s.cfg.RouterID,
			ListenPort:      s.cfg.ListenPort,
			ListenAddresses: []string{s.cfg.ListenAddr},
		},
	}); err != nil {
		return fmt.Errorf("start bgp: %w", err)
	}

	s.log.Info("BGP server started",
		zap.Uint32("asn", s.cfg.ASN),
		zap.String("router_id", s.cfg.RouterID),
		zap.String("listen", fmt.Sprintf("%s:%d", s.cfg.ListenAddr, s.cfg.ListenPort)),
	)

	// Watch best-path changes and install/remove kernel routes.
	go s.watchBestPaths(ctx)

	// Block until context cancelled.
	<-ctx.Done()
	return s.stop()
}

func (s *Speaker) stop() error {
	return s.server.StopBgp(context.Background(), &api.StopBgpRequest{})
}

// ─── Peer management ──────────────────────────────────────────────────────────

// AddPeer registers a BGP neighbor. Sessions are initiated actively (the
// speaker will TCP-connect to peerAddr:179).
func (s *Speaker) AddPeer(ctx context.Context, peerAddr string, peerASN uint32) error {
	ht := s.cfg.HoldTime
	ka := s.cfg.Keepalive

	err := s.server.AddPeer(ctx, &api.AddPeerRequest{
		Peer: &api.Peer{
			Conf: &api.PeerConf{
				NeighborAddress: peerAddr,
				PeerAsn:         peerASN,
			},
			Timers: &api.Timers{
				Config: &api.TimersConfig{
					HoldTime:          ht,
					KeepaliveInterval: ka,
					ConnectRetry:      30,
				},
			},
			AfiSafis: []*api.AfiSafi{
				{Config: &api.AfiSafiConfig{
					Family: &api.Family{
						Afi:  api.Family_AFI_IP,
						Safi: api.Family_SAFI_UNICAST,
					},
				}},
			},
			GracefulRestart: &api.GracefulRestart{
				Config: &api.GracefulRestartConfig{
					Enabled:             true,
					RestartTime:         120,
					LonglivedEnabled:    false,
					NotificationEnabled: true,
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("add bgp peer %s (ASN %d): %w", peerAddr, peerASN, err)
	}
	s.log.Info("BGP peer added", zap.String("peer", peerAddr), zap.Uint32("peer_asn", peerASN))
	return nil
}

// RemovePeer tears down the BGP session to peerAddr and removes all routes
// learned from that peer from the RIB (GoBGP handles this automatically).
func (s *Speaker) RemovePeer(ctx context.Context, peerAddr string) error {
	if err := s.server.DeletePeer(ctx, &api.DeletePeerRequest{Address: peerAddr}); err != nil {
		return fmt.Errorf("remove bgp peer %s: %w", peerAddr, err)
	}
	s.log.Info("BGP peer removed", zap.String("peer", peerAddr))
	return nil
}

// ─── Route management ─────────────────────────────────────────────────────────

// AnnounceRoute originates a locally sourced route into the BGP RIB and
// propagates it to all peers matching applicable export policies.
// nextHop should be this router's address on the relevant interface.
func (s *Speaker) AnnounceRoute(ctx context.Context, prefix, nextHop string) error {
	_, cidr, err := net.ParseCIDR(prefix)
	if err != nil {
		return fmt.Errorf("parse prefix %s: %w", prefix, err)
	}
	prefixLen, _ := cidr.Mask.Size()

	nlri, err := anypb.New(&api.IPAddressPrefix{
		Prefix:    cidr.IP.String(),
		PrefixLen: uint32(prefixLen),
	})
	if err != nil {
		return err
	}

	origin, _ := anypb.New(&api.OriginAttribute{Origin: 0}) // IGP
	nh, _ := anypb.New(&api.NextHopAttribute{NextHop: nextHop})
	asPath, _ := anypb.New(&api.AsPathAttribute{
		Segments: []*api.AsSegment{{
			Type:    2, // AS_SEQUENCE
			Numbers: []uint32{s.cfg.ASN},
		}},
	})
	localPref, _ := anypb.New(&api.LocalPrefAttribute{LocalPref: 100})

	resp, err := s.server.AddPath(ctx, &api.AddPathRequest{
		Path: &api.Path{
			Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
			Nlri:   nlri,
			Pattrs: []*anypb.Any{origin, nh, asPath, localPref},
		},
	})
	if err != nil {
		return fmt.Errorf("announce route %s: %w", prefix, err)
	}

	s.mu.Lock()
	s.pathUUIDs[cidr.String()] = resp.Uuid
	s.mu.Unlock()

	s.log.Info("Route announced", zap.String("prefix", cidr.String()), zap.String("next_hop", nextHop))
	return nil
}

// WithdrawRoute removes a locally originated route from the RIB.
func (s *Speaker) WithdrawRoute(ctx context.Context, prefix string) error {
	_, cidr, err := net.ParseCIDR(prefix)
	if err != nil {
		return fmt.Errorf("parse prefix %s: %w", prefix, err)
	}
	key := cidr.String()

	s.mu.Lock()
	uuid, ok := s.pathUUIDs[key]
	s.mu.Unlock()

	if !ok {
		s.log.Warn("WithdrawRoute: route not found in local table", zap.String("prefix", key))
		return nil // not an error — may have been withdrawn already
	}

	if err := s.server.DeletePath(ctx, &api.DeletePathRequest{Uuid: uuid}); err != nil {
		return fmt.Errorf("withdraw route %s: %w", key, err)
	}

	s.mu.Lock()
	delete(s.pathUUIDs, key)
	s.mu.Unlock()

	s.log.Info("Route withdrawn", zap.String("prefix", key))
	return nil
}

// ListRIB returns all IPv4 unicast routes currently in the Adj-RIB-In-PostPolicy
// (i.e. routes accepted after import policy, installed by peers).
func (s *Speaker) ListRIB(ctx context.Context) ([]RIBEntry, error) {
	var entries []RIBEntry
	fn := func(d *api.Destination) {
		for _, p := range d.Paths {
			e := RIBEntry{
				Prefix: d.Prefix,
				Best:   p.Best,
			}
			for _, a := range p.Pattrs {
				var nh api.NextHopAttribute
				if err := a.UnmarshalTo(&nh); err == nil {
					e.NextHop = nh.NextHop
				}
			}
			entries = append(entries, e)
		}
	}
	err := s.server.ListPath(ctx, &api.ListPathRequest{
		TableType: api.TableType_GLOBAL,
		Family:    &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
	}, fn)
	return entries, err
}

// RIBEntry is a simplified view of a single BGP path.
type RIBEntry struct {
	Prefix  string
	NextHop string
	Best    bool
}

// Server exposes the underlying GoBGP server for advanced use (e.g. policy
// configuration in policy.go).
func (s *Speaker) Server() *server.BgpServer { return s.server }

// ─── Best-path watcher / FIB injection ───────────────────────────────────────

func (s *Speaker) watchBestPaths(ctx context.Context) {
	err := s.server.WatchEvent(ctx, &api.WatchEventRequest{
		BestPath: &api.WatchEventRequest_BestPath{},
	}, func(r *api.WatchEventResponse) {
		bp, ok := r.Event.(*api.WatchEventResponse_BestPath)
		if !ok {
			return
		}
		for _, path := range bp.BestPath.Paths {
			s.handleBestPath(path)
		}
	})
	if err != nil && ctx.Err() == nil {
		s.log.Error("BGP best-path watcher exited", zap.Error(err))
	}
}

func (s *Speaker) handleBestPath(path *api.Path) {
	if s.cfg.WGInterface == "" {
		return
	}

	// Decode NLRI.
	var prefix api.IPAddressPrefix
	if err := path.Nlri.UnmarshalTo(&prefix); err != nil {
		return
	}
	_, cidr, err := net.ParseCIDR(fmt.Sprintf("%s/%d", prefix.Prefix, prefix.PrefixLen))
	if err != nil {
		return
	}

	if path.IsWithdraw {
		if err := s.removeKernelRoute(cidr); err != nil {
			s.log.Warn("FIB: failed to remove route",
				zap.String("prefix", cidr.String()), zap.Error(err))
		}
		return
	}

	// Decode next-hop.
	var nextHop net.IP
	var originASN uint32
	for _, a := range path.Pattrs {
		var nh api.NextHopAttribute
		if err := a.UnmarshalTo(&nh); err == nil {
			nextHop = net.ParseIP(nh.NextHop).To4()
			continue
		}
		var asp api.AsPathAttribute
		if err := a.UnmarshalTo(&asp); err == nil {
			// Last segment's last ASN is the origin.
			if len(asp.Segments) > 0 {
				seg := asp.Segments[len(asp.Segments)-1]
				if len(seg.Numbers) > 0 {
					originASN = seg.Numbers[len(seg.Numbers)-1]
				}
			}
		}
	}

	// Only install routes from node peers (filter by ASN range).
	if s.cfg.NodeASNRange != nil && !s.cfg.NodeASNRange.Contains(originASN) {
		return
	}

	if nextHop == nil {
		s.log.Warn("FIB: no next-hop in best path", zap.String("prefix", cidr.String()))
		return
	}

	if err := s.installKernelRoute(cidr, nextHop); err != nil {
		s.log.Error("FIB: failed to install route",
			zap.String("prefix", cidr.String()),
			zap.String("next_hop", nextHop.String()),
			zap.Error(err))
	}
}

func (s *Speaker) installKernelRoute(dst *net.IPNet, gw net.IP) error {
	link, err := netlink.LinkByName(s.cfg.WGInterface)
	if err != nil {
		return fmt.Errorf("link %s not found: %w", s.cfg.WGInterface, err)
	}
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dst,
		Gw:        gw,
		Protocol:  netlink.RouteProtocol(186), // BGP
	}
	if err := netlink.RouteReplace(route); err != nil {
		return err
	}
	s.log.Info("FIB: installed route",
		zap.String("prefix", dst.String()),
		zap.String("gw", gw.String()),
		zap.String("iface", s.cfg.WGInterface),
	)
	return nil
}

func (s *Speaker) removeKernelRoute(dst *net.IPNet) error {
	if err := netlink.RouteDel(&netlink.Route{Dst: dst}); err != nil {
		return err
	}
	s.log.Info("FIB: removed route", zap.String("prefix", dst.String()))
	return nil
}

// ─── GoBGP logger adapter ─────────────────────────────────────────────────────

// zapLogger bridges GoBGP's internal logger interface to zap.
type zapLogger struct{ l *zap.Logger }

func (z *zapLogger) Panic(msg string, fields server.LogFields)  { z.l.Panic(msg, toZapFields(fields)...) }
func (z *zapLogger) Fatal(msg string, fields server.LogFields)  { z.l.Fatal(msg, toZapFields(fields)...) }
func (z *zapLogger) Error(msg string, fields server.LogFields)  { z.l.Error(msg, toZapFields(fields)...) }
func (z *zapLogger) Warn(msg string, fields server.LogFields)   { z.l.Warn(msg, toZapFields(fields)...) }
func (z *zapLogger) Info(msg string, fields server.LogFields)   { z.l.Info(msg, toZapFields(fields)...) }
func (z *zapLogger) Debug(msg string, fields server.LogFields)  { z.l.Debug(msg, toZapFields(fields)...) }
func (z *zapLogger) Trace(msg string, fields server.LogFields)  { z.l.Debug(msg, toZapFields(fields)...) }
func (z *zapLogger) GetLevel() server.LogLevel                  { return server.LogLevel(0) }
func (z *zapLogger) SetLevel(level server.LogLevel)             {}

func toZapFields(fields server.LogFields) []zap.Field {
	out := make([]zap.Field, 0, len(fields))
	for k, v := range fields {
		out = append(out, zap.Any(k, v))
	}
	return out
}

// ─── Utility ──────────────────────────────────────────────────────────────────

// IPToUint32 converts a 4-byte IPv4 address to uint32 (big-endian).
// Exported for use in subnet logic.
func IPToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip)
}
