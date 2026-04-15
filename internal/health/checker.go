// Package health periodically sweeps the node registry and marks nodes as
// down when their heartbeat lapses beyond the configured timeout.
//
// Failure detection timeline:
//   - Nodes send heartbeats every ~30 s (HeartbeatInterval in AgentConfig).
//   - BGP hold-timer is 90 s: GoBGP withdraws routes after 3 missed keepalives.
//   - Health checker timeout (default 90 s) provides an independent signal that
//     can trigger additional actions (alerts, blackhole routes, etc.) at the
//     same time or faster than the BGP hold timer.
//
// Recovery:
//   - When the node re-registers or sends a heartbeat after being down, the
//     registry transitions it back to active and restores the BGP peer.
package health

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// NodeLister is the subset of the registry needed by the Checker.
type NodeLister interface {
	ListNodes() []NodeSnapshot
	MarkDown(nodeID string)
}

// NodeSnapshot is a moment-in-time view of a node.
type NodeSnapshot struct {
	ID            string
	State         string // "pending" | "active" | "down"
	LastHeartbeat time.Time
}

// Checker runs a periodic sweep and calls registry.MarkDown for any node
// whose heartbeat has lapsed.
type Checker struct {
	registry  NodeLister
	timeout   time.Duration
	interval  time.Duration
	log       *zap.Logger
	onFailure func(nodeID string) // optional: called once per failure transition
}

// NewChecker creates a Checker. onFailure may be nil.
func NewChecker(
	registry NodeLister,
	timeout time.Duration,
	interval time.Duration,
	onFailure func(nodeID string),
	log *zap.Logger,
) *Checker {
	return &Checker{
		registry:  registry,
		timeout:   timeout,
		interval:  interval,
		log:       log,
		onFailure: onFailure,
	}
}

// Run starts the sweep loop. It returns when ctx is cancelled.
func (c *Checker) Run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	c.log.Info("Health checker started",
		zap.Duration("timeout", c.timeout),
		zap.Duration("interval", c.interval),
	)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sweep()
		}
	}
}

func (c *Checker) sweep() {
	now := time.Now()
	for _, n := range c.registry.ListNodes() {
		if n.State == "down" {
			continue // already marked down
		}
		if now.Sub(n.LastHeartbeat) > c.timeout {
			c.log.Warn("Node heartbeat timeout — marking down",
				zap.String("node_id", n.ID),
				zap.Duration("silent_for", now.Sub(n.LastHeartbeat)),
			)
			c.registry.MarkDown(n.ID)
			if c.onFailure != nil {
				c.onFailure(n.ID)
			}
		}
	}
}
