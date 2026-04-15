BINARY_DIR   := bin
CORE_BIN     := $(BINARY_DIR)/bgpd-core
AGENT_BIN    := $(BINARY_DIR)/bgpd-agent
CTL_BIN      := $(BINARY_DIR)/bgpctl

GO           := go
GOFLAGS      := -trimpath
LDFLAGS      := -s -w

.PHONY: all build core agent ctl clean tidy lint proto install

all: build

build: core agent ctl

$(BINARY_DIR):
	mkdir -p $(BINARY_DIR)

core: $(BINARY_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(CORE_BIN) ./cmd/core

agent: $(BINARY_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(AGENT_BIN) ./cmd/agent

ctl: $(BINARY_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(CTL_BIN) ./cmd/bgpctl

# Install binaries to /usr/local/bin (requires root)
install: build
	install -m 0755 $(CORE_BIN)  /usr/local/bin/bgpd-core
	install -m 0755 $(AGENT_BIN) /usr/local/bin/bgpd-agent
	install -m 0755 $(CTL_BIN)   /usr/local/bin/bgpctl

tidy:
	$(GO) mod tidy

lint:
	golangci-lint run ./...

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	       proto/bgpd.proto

clean:
	rm -rf $(BINARY_DIR)

# Generate WireGuard keypair for a new node (output: private.key, public.key)
.PHONY: gen-wgkey
gen-wgkey:
	@wg genkey | tee private.key | wg pubkey > public.key
	@echo "Private key saved to private.key"
	@echo "Public  key saved to public.key"
