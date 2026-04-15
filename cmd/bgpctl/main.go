// bgpctl — operator CLI for managing the distributed BGP routing fabric.
//
// Commands:
//   bgpctl node list               - list all registered nodes
//   bgpctl node show <id>          - show details for a specific node
//   bgpctl node delete <id>        - de-register a node (drains routes)
//   bgpctl subnet list             - list subnet allocations
//   bgpctl route list              - list current BGP/FIB routes
//   bgpctl status                  - overall system health
//
// Configuration (environment or flags):
//   BGPCTL_API_URL    http://10.100.0.1:8080   (core WG IP recommended)
//   BGPCTL_API_KEY    <shared secret>
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	apitypes "github.com/tinybrickboy/router-ui/pkg/api"
)

var (
	apiURL string
	apiKey string
)

func main() {
	root := &cobra.Command{
		Use:   "bgpctl",
		Short: "BGP routing fabric operator CLI",
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			if apiURL == "" {
				apiURL = viper.GetString("api_url")
			}
			if apiKey == "" {
				apiKey = viper.GetString("api_key")
			}
		},
	}

	root.PersistentFlags().StringVar(&apiURL, "api-url", "", "Core API base URL (or BGPCTL_API_URL env)")
	root.PersistentFlags().StringVar(&apiKey, "api-key", "", "API key (or BGPCTL_API_KEY env)")

	viper.SetEnvPrefix("BGPCTL")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	root.AddCommand(
		nodeCmd(),
		subnetCmd(),
		routeCmd(),
		statusCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// ─── node ─────────────────────────────────────────────────────────────────────

func nodeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "node",
		Short: "Manage edge nodes",
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List all registered nodes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var resp apitypes.ListNodesResponse
			if err := apiGet("/nodes", &resp); err != nil {
				return err
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NODE ID\tASN\tSTATE\tWG IP\tSUBNET\tLAST HEARTBEAT\tBGP UP")
			fmt.Fprintln(w, "-------\t---\t-----\t-----\t------\t--------------\t------")
			for _, n := range resp.Nodes {
				age := time.Since(n.LastHeartbeat).Round(time.Second)
				fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s ago\t%v\n",
					n.NodeID, n.ASN, stateColor(string(n.State)),
					n.WGIP, n.AssignedSubnet, age, n.BGPSessionUp)
			}
			return w.Flush()
		},
	}

	show := &cobra.Command{
		Use:   "show <node-id>",
		Short: "Show details for a specific node",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var resp apitypes.ListNodesResponse
			if err := apiGet("/nodes", &resp); err != nil {
				return err
			}
			for _, n := range resp.Nodes {
				if n.NodeID == args[0] {
					printNodeDetail(n)
					return nil
				}
			}
			return fmt.Errorf("node %q not found", args[0])
		},
	}

	del := &cobra.Command{
		Use:   "delete <node-id>",
		Short: "De-register a node (withdraws its BGP routes)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return apiDelete("/nodes/" + args[0])
		},
	}

	cmd.AddCommand(list, show, del)
	return cmd
}

func printNodeDetail(n apitypes.NodeInfo) {
	fmt.Printf("Node ID:         %s\n", n.NodeID)
	fmt.Printf("ASN:             %d\n", n.ASN)
	fmt.Printf("State:           %s\n", stateColor(string(n.State)))
	fmt.Printf("WireGuard IP:    %s\n", n.WGIP)
	fmt.Printf("Assigned Subnet: %s\n", n.AssignedSubnet)
	fmt.Printf("Public IP:       %s\n", n.PublicIP)
	fmt.Printf("BGP Session Up:  %v\n", n.BGPSessionUp)
	fmt.Printf("Last Heartbeat:  %s (%s ago)\n",
		n.LastHeartbeat.Format(time.RFC3339),
		time.Since(n.LastHeartbeat).Round(time.Second))
}

// ─── subnet ───────────────────────────────────────────────────────────────────

func subnetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "subnet",
		Short: "Show subnet allocations",
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List all subnet allocations (inferred from node list)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var resp apitypes.ListNodesResponse
			if err := apiGet("/nodes", &resp); err != nil {
				return err
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "SUBNET\tNODE ID\tSTATE")
			fmt.Fprintln(w, "------\t-------\t-----")
			for _, n := range resp.Nodes {
				fmt.Fprintf(w, "%s\t%s\t%s\n", n.AssignedSubnet, n.NodeID, stateColor(string(n.State)))
			}
			return w.Flush()
		},
	}

	cmd.AddCommand(list)
	return cmd
}

// ─── route ────────────────────────────────────────────────────────────────────

func routeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "route",
		Short: "Show BGP/FIB route table",
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List routes in the core RIB",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var resp apitypes.ListRoutesResponse
			if err := apiGet("/routes", &resp); err != nil {
				return err
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PREFIX\tNEXT HOP\tSOURCE\tACTIVE")
			fmt.Fprintln(w, "------\t--------\t------\t------")
			for _, r := range resp.Routes {
				active := "yes"
				if !r.Active {
					active = "no"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Prefix, r.NextHop, r.Source, active)
			}
			return w.Flush()
		},
	}

	cmd.AddCommand(list)
	return cmd
}

// ─── status ───────────────────────────────────────────────────────────────────

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show overall system health",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var resp apitypes.StatusResponse
			if err := apiGet("/status", &resp); err != nil {
				return err
			}

			health := "HEALTHY"
			if !resp.OK {
				health = "DEGRADED"
			}
			fmt.Printf("Status:         %s\n", health)
			fmt.Printf("Version:        %s\n", resp.Version)
			fmt.Printf("Aggregate:      %s\n", resp.AggregatePrefix)
			fmt.Printf("Nodes (total):  %d\n", resp.NodesTotal)
			fmt.Printf("Nodes (active): %d\n", resp.NodesActive)
			fmt.Printf("Nodes (down):   %d\n", resp.NodesDown)
			if resp.NodesDown > 0 {
				fmt.Println("\nWARN: Some nodes are down. Run `bgpctl node list` for details.")
			}
			return nil
		},
	}
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

func apiGet(path string, out any) error {
	url := strings.TrimRight(apiURL, "/") + "/api/v1" + path
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", apiKey)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var apiErr apitypes.ErrorResponse
		_ = json.Unmarshal(body, &apiErr)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, apiErr.Error)
	}
	return json.Unmarshal(body, out)
}

func apiDelete(path string) error {
	url := strings.TrimRight(apiURL, "/") + "/api/v1" + path
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", apiKey)

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("DELETE %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		var apiErr apitypes.ErrorResponse
		body, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(body, &apiErr)
		return fmt.Errorf("API error %d: %s", resp.StatusCode, apiErr.Error)
	}
	fmt.Println("OK")
	return nil
}

// ─── Misc ─────────────────────────────────────────────────────────────────────

func stateColor(state string) string {
	// Terminal colours (ANSI). Fall back gracefully on non-TTY.
	switch state {
	case "active":
		return "\033[32m" + state + "\033[0m" // green
	case "down":
		return "\033[31m" + state + "\033[0m" // red
	default:
		return "\033[33m" + state + "\033[0m" // yellow
	}
}
