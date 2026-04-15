#!/usr/bin/env bash
# install.sh — build and install bgpd-core, bgpd-agent, bgpctl from source
set -euo pipefail

REPO="https://github.com/tinybrickboy/router-ui.git"
INSTALL_DIR="/usr/local/bin"
CONF_DIR="/etc/bgpd"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# ── Prerequisites ─────────────────────────────────────────────────────────────
command -v go  >/dev/null 2>&1 || error "Go not found. Install from https://go.dev/dl/"
command -v git >/dev/null 2>&1 || error "git not found."
[[ "$(uname -s)" == "Linux" ]]  || error "Only Linux is supported."

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED="1.21"
if [[ "$(printf '%s\n' "$REQUIRED" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED" ]]; then
  error "Go $REQUIRED+ required (found $GO_VERSION)"
fi

# ── Clone ─────────────────────────────────────────────────────────────────────
info "Cloning router-ui into $TMPDIR …"
git clone --depth=1 "$REPO" "$TMPDIR/router-ui"
cd "$TMPDIR/router-ui"

# ── Build ─────────────────────────────────────────────────────────────────────
info "Downloading Go modules …"
go mod download

info "Building binaries …"
go build -trimpath -ldflags "-s -w" -o "$TMPDIR/bgpd-core"  ./cmd/core
go build -trimpath -ldflags "-s -w" -o "$TMPDIR/bgpd-agent" ./cmd/agent
go build -trimpath -ldflags "-s -w" -o "$TMPDIR/bgpctl"     ./cmd/bgpctl

# ── Install ───────────────────────────────────────────────────────────────────
info "Installing to $INSTALL_DIR …"
if [[ "$EUID" -ne 0 ]]; then
  warn "Not running as root — using sudo for installation."
  SUDO=sudo
else
  SUDO=""
fi

$SUDO install -m 0755 "$TMPDIR/bgpd-core"  "$INSTALL_DIR/bgpd-core"
$SUDO install -m 0755 "$TMPDIR/bgpd-agent" "$INSTALL_DIR/bgpd-agent"
$SUDO install -m 0755 "$TMPDIR/bgpctl"     "$INSTALL_DIR/bgpctl"

# ── Config skeleton ───────────────────────────────────────────────────────────
if [[ ! -d "$CONF_DIR" ]]; then
  info "Creating config directory $CONF_DIR …"
  $SUDO mkdir -p "$CONF_DIR"
  $SUDO cp configs/core.yaml  "$CONF_DIR/core.yaml.example"
  $SUDO cp configs/node1.yaml "$CONF_DIR/agent.yaml.example"
  info "Example configs written to $CONF_DIR/*.example"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
info "Installation complete!"
echo ""
echo "  bgpd-core   → $INSTALL_DIR/bgpd-core"
echo "  bgpd-agent  → $INSTALL_DIR/bgpd-agent"
echo "  bgpctl      → $INSTALL_DIR/bgpctl"
echo ""
echo "Next steps:"
echo "  1. Edit $CONF_DIR/core.yaml.example   (copy to core.yaml)"
echo "  2. sudo bgpd-core --config /etc/bgpd/core.yaml"
echo "  3. Open http://<core-ip>:8080 in your browser"
echo ""
