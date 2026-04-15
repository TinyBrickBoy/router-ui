package subnet

import (
	"fmt"
	"testing"
)

func TestNewAllocator_CarveSlash24IntoSlash26(t *testing.T) {
	a, err := NewAllocator("203.0.113.0/24", 26)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	subnets := a.List()
	if len(subnets) != 4 {
		t.Fatalf("expected 4 subnets, got %d", len(subnets))
	}
	want := []string{
		"203.0.113.0/26",
		"203.0.113.64/26",
		"203.0.113.128/26",
		"203.0.113.192/26",
	}
	for i, s := range subnets {
		if s.CIDR.String() != want[i] {
			t.Errorf("subnet[%d]: got %s, want %s", i, s.CIDR, want[i])
		}
		if s.InUse {
			t.Errorf("subnet[%d] should not be in use after creation", i)
		}
	}
}

func TestNewAllocator_CarveSlash24IntoSlash27(t *testing.T) {
	a, err := NewAllocator("10.0.0.0/24", 27)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if got := len(a.List()); got != 8 {
		t.Fatalf("expected 8 subnets for /27 out of /24, got %d", got)
	}
}

func TestNewAllocator_InvalidSubnetBits(t *testing.T) {
	_, err := NewAllocator("203.0.113.0/24", 24)
	if err == nil {
		t.Fatal("expected error when subnetBits == base prefix length")
	}
	_, err = NewAllocator("203.0.113.0/24", 20)
	if err == nil {
		t.Fatal("expected error when subnetBits < base prefix length")
	}
}

func TestAllocate_Sequential(t *testing.T) {
	a, _ := NewAllocator("203.0.113.0/24", 26)

	cidr1, err := a.Allocate("node1")
	if err != nil {
		t.Fatalf("Allocate node1: %v", err)
	}
	if cidr1.String() != "203.0.113.0/26" {
		t.Errorf("node1 got %s, want 203.0.113.0/26", cidr1)
	}

	cidr2, err := a.Allocate("node2")
	if err != nil {
		t.Fatalf("Allocate node2: %v", err)
	}
	if cidr2.String() != "203.0.113.64/26" {
		t.Errorf("node2 got %s, want 203.0.113.64/26", cidr2)
	}
}

func TestAllocate_Idempotent(t *testing.T) {
	a, _ := NewAllocator("203.0.113.0/24", 26)

	cidr1, err := a.Allocate("node1")
	if err != nil {
		t.Fatalf("first Allocate: %v", err)
	}
	cidr2, err := a.Allocate("node1")
	if err != nil {
		t.Fatalf("second Allocate (idempotent): %v", err)
	}
	if cidr1.String() != cidr2.String() {
		t.Errorf("idempotent allocate returned different CIDRs: %s vs %s", cidr1, cidr2)
	}
}

func TestAllocate_Exhaustion(t *testing.T) {
	a, _ := NewAllocator("203.0.113.0/24", 26)
	for i := 0; i < 4; i++ {
		if _, err := a.Allocate(fmt.Sprintf("node%d", i)); err != nil {
			t.Fatalf("Allocate node%d: %v", i, err)
		}
	}
	_, err := a.Allocate("node5")
	if err == nil {
		t.Fatal("expected error when allocating from exhausted pool")
	}
}

func TestRelease_FreesSlot(t *testing.T) {
	a, _ := NewAllocator("203.0.113.0/24", 26)
	_, _ = a.Allocate("node1")
	_, _ = a.Allocate("node2")

	if err := a.Release("node1"); err != nil {
		t.Fatalf("Release node1: %v", err)
	}

	cidr, err := a.Allocate("node3")
	if err != nil {
		t.Fatalf("Allocate node3 after release: %v", err)
	}
	if cidr.String() != "203.0.113.0/26" {
		t.Errorf("expected reclaimed 203.0.113.0/26, got %s", cidr)
	}
}

func TestRelease_UnknownNode(t *testing.T) {
	a, _ := NewAllocator("203.0.113.0/24", 26)
	if err := a.Release("ghost"); err == nil {
		t.Fatal("expected error releasing unknown node")
	}
}

func TestAssignSpecific(t *testing.T) {
	a, _ := NewAllocator("203.0.113.0/24", 26)

	if err := a.AssignSpecific("203.0.113.128/26", "node3"); err != nil {
		t.Fatalf("AssignSpecific: %v", err)
	}
	sub := a.SubnetForNode("node3")
	if sub == nil || sub.String() != "203.0.113.128/26" {
		t.Errorf("SubnetForNode returned %v, want 203.0.113.128/26", sub)
	}
}

func TestAssignSpecific_Conflict(t *testing.T) {
	a, _ := NewAllocator("203.0.113.0/24", 26)
	_ = a.AssignSpecific("203.0.113.0/26", "node1")
	if err := a.AssignSpecific("203.0.113.0/26", "node2"); err == nil {
		t.Fatal("expected conflict error assigning occupied subnet to different node")
	}
}

func TestSubnetForNode_NotAllocated(t *testing.T) {
	a, _ := NewAllocator("203.0.113.0/24", 26)
	if sub := a.SubnetForNode("nobody"); sub != nil {
		t.Errorf("expected nil for unallocated node, got %v", sub)
	}
}

func TestList_Snapshot(t *testing.T) {
	a, _ := NewAllocator("203.0.113.0/24", 26)
	_, _ = a.Allocate("node1")

	list := a.List()
	if !list[0].InUse {
		t.Error("list[0] should be in use")
	}
	// Mutating the snapshot must not affect the allocator's state.
	list[0].NodeID = "tampered"
	list[0].InUse = false

	list2 := a.List()
	if list2[0].NodeID != "node1" || !list2[0].InUse {
		t.Error("List() snapshot mutation leaked into allocator state")
	}
}
