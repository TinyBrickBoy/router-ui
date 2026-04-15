// Package subnet manages the carving and assignment of sub-prefixes from the
// operator's aggregate block (e.g. 203.0.113.0/24 → four /26 subnets).
package subnet

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// Subnet represents one carved sub-prefix.
type Subnet struct {
	CIDR   *net.IPNet
	InUse  bool
	NodeID string // empty if not allocated
}

// String returns a human-readable description.
func (s *Subnet) String() string {
	if s.InUse {
		return fmt.Sprintf("%s → %s", s.CIDR, s.NodeID)
	}
	return fmt.Sprintf("%s (free)", s.CIDR)
}

// Allocator carves a base prefix into equal-sized sub-prefixes and tracks
// which are assigned to which node.
type Allocator struct {
	mu      sync.Mutex
	base    *net.IPNet
	subnets []*Subnet
}

// NewAllocator parses basePrefix (e.g. "203.0.113.0/24") and pre-computes all
// sub-prefixes of length subnetBits (e.g. 26). Returns an error if
// subnetBits <= the base prefix length, or if the base is not an IPv4 prefix.
func NewAllocator(basePrefix string, subnetBits int) (*Allocator, error) {
	_, base, err := net.ParseCIDR(basePrefix)
	if err != nil {
		return nil, fmt.Errorf("parse base prefix %q: %w", basePrefix, err)
	}
	if base.IP.To4() == nil {
		return nil, fmt.Errorf("only IPv4 base prefixes are supported")
	}
	baseBits, _ := base.Mask.Size()
	if subnetBits <= baseBits {
		return nil, fmt.Errorf("subnet_bits (%d) must be > base prefix length (%d)", subnetBits, baseBits)
	}
	if subnetBits > 30 {
		return nil, fmt.Errorf("subnet_bits (%d) is too small (max 30 for /30)", subnetBits)
	}

	subnets, err := carve(base, subnetBits)
	if err != nil {
		return nil, err
	}
	return &Allocator{base: base, subnets: subnets}, nil
}

// Allocate assigns the next available subnet to nodeID.
// Returns an error if all subnets are in use or nodeID is already allocated.
func (a *Allocator) Allocate(nodeID string) (*net.IPNet, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Idempotent: return existing assignment if node already has one.
	for _, s := range a.subnets {
		if s.InUse && s.NodeID == nodeID {
			return s.CIDR, nil
		}
	}

	for _, s := range a.subnets {
		if !s.InUse {
			s.InUse = true
			s.NodeID = nodeID
			return s.CIDR, nil
		}
	}
	return nil, fmt.Errorf("no free subnets available (all %d are allocated)", len(a.subnets))
}

// AssignSpecific assigns a particular CIDR to nodeID. Used when restoring
// state from persistent storage or for operator-forced assignments.
func (a *Allocator) AssignSpecific(cidr string, nodeID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, s := range a.subnets {
		if s.CIDR.String() == cidr {
			if s.InUse && s.NodeID != nodeID {
				return fmt.Errorf("subnet %s is already assigned to %s", cidr, s.NodeID)
			}
			s.InUse = true
			s.NodeID = nodeID
			return nil
		}
	}
	return fmt.Errorf("subnet %s is not part of the allocation pool", cidr)
}

// Release frees the subnet assigned to nodeID.
func (a *Allocator) Release(nodeID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, s := range a.subnets {
		if s.InUse && s.NodeID == nodeID {
			s.InUse = false
			s.NodeID = ""
			return nil
		}
	}
	return fmt.Errorf("node %s has no allocated subnet", nodeID)
}

// List returns a snapshot of all subnets and their allocation state.
func (a *Allocator) List() []*Subnet {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := make([]*Subnet, len(a.subnets))
	for i, s := range a.subnets {
		cp := *s
		ipCopy := make(net.IP, len(s.CIDR.IP))
		copy(ipCopy, s.CIDR.IP)
		maskCopy := make(net.IPMask, len(s.CIDR.Mask))
		copy(maskCopy, s.CIDR.Mask)
		cp.CIDR = &net.IPNet{IP: ipCopy, Mask: maskCopy}
		out[i] = &cp
	}
	return out
}

// Base returns the aggregate prefix.
func (a *Allocator) Base() *net.IPNet { return a.base }

// SubnetForNode returns the subnet assigned to nodeID, or nil.
func (a *Allocator) SubnetForNode(nodeID string) *net.IPNet {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, s := range a.subnets {
		if s.InUse && s.NodeID == nodeID {
			return s.CIDR
		}
	}
	return nil
}

// ─── Internal ─────────────────────────────────────────────────────────────────

// carve splits base into all sub-prefixes of length subnetBits.
func carve(base *net.IPNet, subnetBits int) ([]*Subnet, error) {
	baseIP := base.IP.To4()
	if baseIP == nil {
		return nil, fmt.Errorf("not an IPv4 network")
	}
	baseBits, _ := base.Mask.Size()
	hostBits := subnetBits - baseBits
	count := 1 << hostBits // number of sub-prefixes

	baseInt := ipToUint32(baseIP)
	subnetSize := uint32(1) << (32 - subnetBits)

	subnets := make([]*Subnet, 0, count)
	for i := 0; i < count; i++ {
		ip := uint32ToIP(baseInt + uint32(i)*subnetSize)
		mask := net.CIDRMask(subnetBits, 32)
		subnets = append(subnets, &Subnet{
			CIDR: &net.IPNet{IP: ip.Mask(mask), Mask: mask},
		})
	}
	return subnets, nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
