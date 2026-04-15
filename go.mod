module github.com/tinybrickboy/router-ui

go 1.21

require (
	github.com/osrg/gobgp/v3 v3.26.0
	github.com/spf13/cobra v1.8.0
	github.com/spf13/viper v1.18.2
	github.com/vishvananda/netlink v1.3.0
	go.uber.org/zap v1.27.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6
	google.golang.org/protobuf v1.34.1
)

// Run `go mod tidy` after cloning to resolve all transitive dependencies.
// Key transitive deps pulled in by gobgp: google.golang.org/grpc, github.com/eapache/go-resiliency, etc.
