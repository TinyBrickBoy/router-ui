// policy.go configures GoBGP import/export policies on the core router.
//
// GoBGP v3.26 API notes (differs from older docs):
//   - PolicyAssignment.DefaultAction is RouteAction (not DefaultPolicyType)
//   - ApplyPolicy has InPolicy/ExportPolicy/ImportPolicy (*PolicyAssignment)
//   - No ApplyPolicyConfig wrapper type exists
//
// Policy architecture:
//
//	IMPORT (peer → Local RIB):
//	  Accept only prefixes that fall within the aggregate /24 at exactly
//	  SubnetBits length (/26 or /27). Reject everything else.
//
//	EXPORT (Local RIB → upstream ISP peers):
//	  Announce only the aggregate /24. Never leak node /26 routes upstream.
//
//	EXPORT (Local RIB → node peers):
//	  Left as accept-all (nodes may receive a default route if desired).
package bgp

import (
	"context"
	"fmt"
	"net"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"go.uber.org/zap"
)

// PolicyManager configures route policies on a running GoBGP server.
type PolicyManager struct {
	srv             *server.BgpServer
	aggregatePrefix string // e.g. "203.0.113.0/24"
	subnetBits      int    // e.g. 26
	log             *zap.Logger
}

// NewPolicyManager creates a policy manager targeting srv.
func NewPolicyManager(srv *server.BgpServer, aggregatePrefix string, subnetBits int, log *zap.Logger) *PolicyManager {
	return &PolicyManager{
		srv:             srv,
		aggregatePrefix: aggregatePrefix,
		subnetBits:      subnetBits,
		log:             log,
	}
}

// Apply installs all policies on the server. Call after StartBgp.
func (pm *PolicyManager) Apply(ctx context.Context) error {
	if err := pm.addPrefixSets(ctx); err != nil {
		return fmt.Errorf("add prefix sets: %w", err)
	}
	if err := pm.addPolicies(ctx); err != nil {
		return fmt.Errorf("add policies: %w", err)
	}
	if err := pm.assignGlobalImport(ctx); err != nil {
		return fmt.Errorf("assign global import policy: %w", err)
	}
	pm.log.Info("BGP policies applied",
		zap.String("aggregate", pm.aggregatePrefix),
		zap.Int("subnet_bits", pm.subnetBits),
	)
	return nil
}

// ─── Prefix sets ──────────────────────────────────────────────────────────────

func (pm *PolicyManager) addPrefixSets(ctx context.Context) error {
	_, aggNet, err := net.ParseCIDR(pm.aggregatePrefix)
	if err != nil {
		return fmt.Errorf("parse aggregate prefix: %w", err)
	}
	aggBits, _ := aggNet.Mask.Size()

	// "node-subnets": prefixes inside the aggregate at exactly subnetBits length.
	nodePfxSet := &api.DefinedSet{
		DefinedType: api.DefinedType_PREFIX,
		Name:        "node-subnets",
		Prefixes: []*api.Prefix{{
			IpPrefix:      pm.aggregatePrefix,
			MaskLengthMin: uint32(pm.subnetBits),
			MaskLengthMax: uint32(pm.subnetBits),
		}},
	}
	if err := pm.srv.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: nodePfxSet}); err != nil {
		return fmt.Errorf("add node-subnets prefix set: %w", err)
	}

	// "aggregate-only": the exact /N aggregate (for upstream export).
	aggPfxSet := &api.DefinedSet{
		DefinedType: api.DefinedType_PREFIX,
		Name:        "aggregate-only",
		Prefixes: []*api.Prefix{{
			IpPrefix:      pm.aggregatePrefix,
			MaskLengthMin: uint32(aggBits),
			MaskLengthMax: uint32(aggBits),
		}},
	}
	if err := pm.srv.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: aggPfxSet}); err != nil {
		return fmt.Errorf("add aggregate-only prefix set: %w", err)
	}

	return nil
}

// ─── Policies ─────────────────────────────────────────────────────────────────

func (pm *PolicyManager) addPolicies(ctx context.Context) error {
	// import-from-nodes: accept /subnetBits routes within the aggregate.
	importPolicy := &api.Policy{
		Name: "import-from-nodes",
		Statements: []*api.Statement{{
			Name: "accept-node-subnets",
			Conditions: &api.Conditions{
				PrefixSet: &api.MatchSet{
					Name: "node-subnets",
					Type: api.MatchSet_ANY,
				},
			},
			Actions: &api.Actions{
				RouteAction: api.RouteAction_ACCEPT,
			},
		}},
	}
	if err := pm.srv.AddPolicy(ctx, &api.AddPolicyRequest{
		Policy:                  importPolicy,
		ReferExistingStatements: false,
	}); err != nil {
		return fmt.Errorf("add import-from-nodes policy: %w", err)
	}

	// export-aggregate-only: only announce the /24 aggregate to upstream peers.
	exportPolicy := &api.Policy{
		Name: "export-aggregate-only",
		Statements: []*api.Statement{{
			Name: "allow-aggregate",
			Conditions: &api.Conditions{
				PrefixSet: &api.MatchSet{
					Name: "aggregate-only",
					Type: api.MatchSet_ANY,
				},
			},
			Actions: &api.Actions{
				RouteAction: api.RouteAction_ACCEPT,
			},
		}},
	}
	if err := pm.srv.AddPolicy(ctx, &api.AddPolicyRequest{
		Policy:                  exportPolicy,
		ReferExistingStatements: false,
	}); err != nil {
		return fmt.Errorf("add export-aggregate-only policy: %w", err)
	}

	return nil
}

// ─── Policy assignment ────────────────────────────────────────────────────────

// assignGlobalImport sets the global import policy so only node subnets enter
// the Local RIB. DefaultAction is RouteAction_REJECT (v3.26 API).
func (pm *PolicyManager) assignGlobalImport(ctx context.Context) error {
	return pm.srv.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          "",
			Direction:     api.PolicyDirection_IMPORT,
			Policies:      []*api.Policy{{Name: "import-from-nodes"}},
			DefaultAction: api.RouteAction_REJECT,
		},
	})
}

// AddUpstreamExportPolicy assigns the export-aggregate-only policy to a
// specific upstream peer (per-peer export policy, reject everything else).
// Call after AddPeer for each upstream.
func AddUpstreamExportPolicy(ctx context.Context, srv *server.BgpServer, peerAddr string) error {
	return srv.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
		Assignment: &api.PolicyAssignment{
			Name:          peerAddr,
			Direction:     api.PolicyDirection_EXPORT,
			Policies:      []*api.Policy{{Name: "export-aggregate-only"}},
			DefaultAction: api.RouteAction_REJECT,
		},
	})
}
