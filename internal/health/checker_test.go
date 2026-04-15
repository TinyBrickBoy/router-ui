package health

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

// fakeRegistry is a test-double for NodeLister.
type fakeRegistry struct {
	mu    sync.Mutex
	nodes []NodeSnapshot
	downs []string
}

func (f *fakeRegistry) ListNodes() []NodeSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]NodeSnapshot, len(f.nodes))
	copy(out, f.nodes)
	return out
}

func (f *fakeRegistry) MarkDown(nodeID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.downs = append(f.downs, nodeID)
	for i, n := range f.nodes {
		if n.ID == nodeID {
			f.nodes[i].State = "down"
		}
	}
}

func (f *fakeRegistry) markedDown() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.downs))
	copy(out, f.downs)
	return out
}

func newLogger() *zap.Logger {
	l, _ := zap.NewDevelopment()
	return l
}

func TestSweep_MarksStalledNodeDown(t *testing.T) {
	reg := &fakeRegistry{
		nodes: []NodeSnapshot{
			{ID: "node1", State: "active", LastHeartbeat: time.Now().Add(-2 * time.Minute)},
		},
	}
	var failureCalls []string
	c := NewChecker(reg, 90*time.Second, time.Minute, func(id string) {
		failureCalls = append(failureCalls, id)
	}, newLogger())

	c.sweep()

	downs := reg.markedDown()
	if len(downs) != 1 || downs[0] != "node1" {
		t.Errorf("expected node1 to be marked down, got %v", downs)
	}
	if len(failureCalls) != 1 || failureCalls[0] != "node1" {
		t.Errorf("onFailure not called with node1, got %v", failureCalls)
	}
}

func TestSweep_DoesNotMarkHealthyNodeDown(t *testing.T) {
	reg := &fakeRegistry{
		nodes: []NodeSnapshot{
			{ID: "node1", State: "active", LastHeartbeat: time.Now().Add(-10 * time.Second)},
		},
	}
	c := NewChecker(reg, 90*time.Second, time.Minute, nil, newLogger())
	c.sweep()

	if downs := reg.markedDown(); len(downs) != 0 {
		t.Errorf("expected no downs, got %v", downs)
	}
}

func TestSweep_SkipsAlreadyDownNodes(t *testing.T) {
	reg := &fakeRegistry{
		nodes: []NodeSnapshot{
			{ID: "node1", State: "down", LastHeartbeat: time.Now().Add(-5 * time.Minute)},
		},
	}
	var failureCalls int
	c := NewChecker(reg, 90*time.Second, time.Minute, func(_ string) { failureCalls++ }, newLogger())
	c.sweep()
	c.sweep() // second sweep should also skip

	if failureCalls != 0 {
		t.Errorf("onFailure should not be called for already-down nodes, called %d times", failureCalls)
	}
	// MarkDown should not be called again for already-down node
	if downs := reg.markedDown(); len(downs) != 0 {
		t.Errorf("MarkDown called for already-down node: %v", downs)
	}
}

func TestSweep_MultipleNodes(t *testing.T) {
	reg := &fakeRegistry{
		nodes: []NodeSnapshot{
			{ID: "healthy", State: "active", LastHeartbeat: time.Now().Add(-5 * time.Second)},
			{ID: "stale1", State: "active", LastHeartbeat: time.Now().Add(-3 * time.Minute)},
			{ID: "stale2", State: "active", LastHeartbeat: time.Now().Add(-10 * time.Minute)},
		},
	}
	c := NewChecker(reg, 90*time.Second, time.Minute, nil, newLogger())
	c.sweep()

	downs := reg.markedDown()
	if len(downs) != 2 {
		t.Fatalf("expected 2 nodes marked down, got %v", downs)
	}
	downSet := map[string]bool{downs[0]: true, downs[1]: true}
	if !downSet["stale1"] || !downSet["stale2"] {
		t.Errorf("wrong nodes marked down: %v", downs)
	}
}

func TestRun_CancelStopsLoop(t *testing.T) {
	reg := &fakeRegistry{}
	c := NewChecker(reg, 90*time.Second, 50*time.Millisecond, nil, newLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()

	select {
	case <-done:
		// expected
	case <-time.After(time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}
