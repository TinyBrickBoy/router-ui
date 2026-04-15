# router-ui — Distributed BGP Routing System

A production-grade distributed BGP + WireGuard routing fabric written in Go.
Split a `/24` prefix across multiple nodes in different datacenters, with
automatic failover, a web dashboard, and a CLI management tool.

```
Internet / Upstream ISP
        │  eBGP  203.0.113.0/24
        ▼
  ┌─────────────┐   WireGuard hub (iBGP, same ASN)
  │  Core Router│──────────────────────────────────────┐
  │  bgpd-core  │         │               │            │
  │  Web UI :80 │    ┌────▼────┐    ┌─────▼───┐   ┌───▼─────┐
  └─────────────┘    │ Node 1  │    │ Node 2  │   │ Node 3  │
                     │.0/26    │    │.64/26   │   │.128/26  │
                     │bgpd-agnt│    │bgpd-agnt│   │bgpd-agnt│
                     └─────────┘    └─────────┘   └─────────┘
```

## Features

- **Single ASN** — iBGP between core and all nodes (no per-node ASN needed)
- **WireGuard** — all BGP sessions and management traffic run inside the tunnel
- **Automatic failover** — heartbeat monitor + BGP hold-timer withdraw routes within ≤90 s
- **Web dashboard** — real-time node status, route table, subnet map
- **CLI** (`bgpctl`) — list nodes, routes, subnets; delete nodes
- **No external daemons** — GoBGP is embedded; no BIRD/FRR/Zebra required

## Quick Start

> Requires: Linux, Go 1.21+, root / `CAP_NET_ADMIN` for WireGuard & BGP port 179.

```bash
# 1. Clone & build
git clone https://github.com/tinybrickboy/router-ui.git
cd router-ui
go mod tidy
make build          # → bin/bgpd-core  bin/bgpd-agent  bin/bgpctl
sudo make install   # → /usr/local/bin/

# 2. Generate a WireGuard key for the core
wg genkey | tee /etc/bgpd/core.key | wg pubkey > /etc/bgpd/core.pub
# Copy the private key into configs/core.yaml → wireguard.private_key

# 3. Configure the core
cp configs/core.yaml /etc/bgpd/core.yaml
# Edit: bgp.asn, bgp.router_id, wireguard.private_key,
#       network.aggregate_prefix, bgp.upstreams, api.api_key

# 4. Start the core
sudo bgpd-core --config /etc/bgpd/core.yaml

# 5. Open the web dashboard
#    http://<core-public-ip>:8080
```

### One-liner install (build from source)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/tinybrickboy/router-ui/main/scripts/install.sh)
```

### Add a node

```bash
# On the node server:
cp configs/node1.yaml /etc/bgpd/agent.yaml
# Edit: node_id, core.public_ip, core.api_key, wireguard.public_ip
# Leave wireguard.private_key empty — a key is generated on first run.

sudo bgpd-agent --config /etc/bgpd/agent.yaml
# On first run the agent prints: "Generated new WireGuard keypair"
# Copy the private_key value into agent.yaml to persist it.
```

## Configuration

### Core (`/etc/bgpd/core.yaml`)

| Key | Example | Description |
|-----|---------|-------------|
| `bgp.asn` | `65000` | Your ASN (same on all nodes) |
| `bgp.router_id` | `10.100.0.1` | BGP router-id (= core WG IP) |
| `bgp.upstreams` | see below | Upstream ISP eBGP peers |
| `wireguard.private_key` | `<base64>` | Core WG private key |
| `wireguard.address` | `10.100.0.1/24` | Core WG interface IP |
| `network.aggregate_prefix` | `203.0.113.0/24` | Your owned /24 block |
| `network.subnet_bits` | `26` | Split into /26 subnets (4 nodes max) |
| `api.api_key` | `<secret>` | Shared key for node auth |
| `api.listen` | `0.0.0.0:8080` | HTTP API + Web UI listen address |

### Node (`/etc/bgpd/agent.yaml`)

| Key | Example | Description |
|-----|---------|-------------|
| `node_id` | `node1` | Unique node name |
| `core.public_ip` | `198.51.100.100` | Core's public IP |
| `core.api_key` | `<secret>` | Must match core's `api.api_key` |
| `wireguard.public_ip` | `203.0.113.10` | This node's public IP |
| `wireguard.private_key` | `<base64>` | WG private key (generated on first run) |

## CLI usage

```bash
export BGPCTL_API_URL=http://10.100.0.1:8080
export BGPCTL_API_KEY=your_secret

bgpctl status           # overall health
bgpctl node list        # all nodes with state + heartbeat age
bgpctl node show node1  # full detail for one node
bgpctl node delete node2  # drain & de-register a node
bgpctl route list       # BGP RIB
bgpctl subnet list      # subnet allocation
```

## Routing flow

```
1. bgpd-agent starts → registers via POST /api/v1/nodes/register
2. Core allocates WG IP (10.100.0.x) + subnet (203.0.113.x/26)
3. Core adds WG peer + iBGP session for the node
4. Agent configures wg0 → tunnel comes up
5. Agent announces 203.0.113.x/26  NEXT_HOP=10.100.0.x  via iBGP
6. Core best-path watcher: installs  203.0.113.x/26 via 10.100.0.x dev wg-core
7. Traffic: ISP → Core → WireGuard → Node
8. Failure: heartbeat timeout → BGP peer removed → routes withdrawn → ISP stops routing
9. Recovery: agent re-registers → tunnel + BGP re-establish → routes restored
```

## Systemd units

```ini
# /etc/systemd/system/bgpd-core.service
[Unit]
Description=BGP Core Router
After=network.target

[Service]
ExecStart=/usr/local/bin/bgpd-core --config /etc/bgpd/core.yaml
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/bgpd-agent.service
[Unit]
Description=BGP Node Agent
After=network.target

[Service]
ExecStart=/usr/local/bin/bgpd-agent --config /etc/bgpd/agent.yaml
Restart=on-failure
RestartSec=10
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now bgpd-core    # on core
systemctl enable --now bgpd-agent   # on each node
```

## Building

```bash
make build      # all three binaries
make core       # bgpd-core only
make agent      # bgpd-agent only
make ctl        # bgpctl only
make install    # copy to /usr/local/bin (needs root)
make tidy       # go mod tidy
make lint       # golangci-lint
```

## Project layout

```
cmd/
  core/       bgpd-core daemon
  agent/      bgpd-agent daemon
  bgpctl/     operator CLI
internal/
  bgp/        embedded GoBGP speaker + FIB injection
  wireguard/  interface & peer management (wgctrl + netlink)
  subnet/     /24 → /26 allocator
  registry/   node state store + HTTP control-plane
  health/     heartbeat monitor
  webui/      web dashboard handler
web/
  index.html  single-page dashboard (embedded in binary)
pkg/
  config/     CoreConfig + AgentConfig
  api/        shared HTTP JSON types
configs/      example YAML configs
proto/        gRPC reference (optional; HTTP/JSON used by default)
```

## License

See [LICENSE](LICENSE).
