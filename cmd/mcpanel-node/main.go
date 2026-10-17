// Command mcpanel-node is the MC panel node daemon (M1).
//
// Commands:
//
//	join          one command to enroll + serve (panel URL argument; token
//	              via --token, MCNODE_ENROLL_TOKEN, or an interactive prompt)
//	enroll        bootstrap against the panel (node -> panel HTTPS)
//	serve         run the control channel WSS server (panel dials in)
//	fingerprint   print the local TLS leaf certificate SHA-256 pin
//	dev-credential  write a local credential for cross-language integration
//	              testing without the panel bootstrap (dev only, entropy
//	              rules still enforced)
//	version       print the agent version
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/yudream/mcpanel-node/internal/app"
	"github.com/yudream/mcpanel-node/internal/certutil"
	"github.com/yudream/mcpanel-node/internal/config"
	"github.com/yudream/mcpanel-node/internal/credential"
	"github.com/yudream/mcpanel-node/internal/logutil"
	"github.com/yudream/mcpanel-node/internal/version"
)

// generateSecret produces a 32-byte random secret encoded as 43 base64url
// chars — the same shape the panel issues at bootstrap. Used only by the
// TEST ONLY dev-credential command; it is printed once to stdout and never
// logged through the structured logger.
func generateSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// readTokenLine reads one pasted line from stdin as an interactive token
// entry. Stdin input never reaches shell history (unlike command-line
// arguments); it may be echoed by the terminal, which is acceptable for an
// attended paste of a short-lived one-time token.
func readTokenLine() (string, error) {
	fmt.Fprint(os.Stderr, "paste one-time enroll token (input never enters shell history): ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read token from stdin: %w", err)
	}
	token := strings.TrimSpace(line)
	if token == "" {
		return "", errors.New("empty enroll token")
	}
	return token, nil
}

func main() {
	root := &cobra.Command{
		Use:           "mcpanel-node",
		Short:         "MC panel node daemon",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().String("config", "", "path to config.yaml (defaults apply when empty)")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := func(cfg *config.Config) *slog.Logger { return logutil.New(os.Stderr, cfg.LogLevel) }

	// loadConfig reads the config file (optional) and applies the command's
	// --data-dir / --listen overrides.
	loadConfig := func(cmd *cobra.Command) (*config.Config, error) {
		cfgPath, _ := cmd.Flags().GetString("config")
		if cfgPath == "" {
			cfgPath, _ = root.PersistentFlags().GetString("config")
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			return nil, err
		}
		if v, _ := cmd.Flags().GetString("data-dir"); v != "" {
			cfg.DataDir = v
		}
		if v, _ := cmd.Flags().GetString("listen"); v != "" {
			cfg.Listen = v
		}
		return cfg, nil
	}

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the agent version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("mcpanel-node " + version.Version)
			return nil
		},
	})

	enrollCmd := &cobra.Command{
		Use:   "enroll",
		Short: "Bootstrap against the panel with the one-time enroll token",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			log := logger(cfg)
			_, err = app.Enroll(cmd.Context(), cfg, log)
			return err
		},
	}
	enrollCmd.Flags().String("data-dir", "", "override config dataDir")
	root.AddCommand(enrollCmd)

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the control channel WSS server (panel dials in)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			log := logger(cfg)
			// Single-command container bootstrap: with no local credential but a
			// token (MCNODE_ENROLL_TOKEN / enroll.token) and panel.url present,
			// enroll first so `docker run ... -e ... node` works without a
			// separate enroll step. Requires nothing from the command line.
			credStore := credential.NewStore(cfg.DataDir, cfg.Credential.Path)
			if !credStore.Exists() && strings.TrimSpace(cfg.Enroll.Token) != "" && strings.TrimSpace(cfg.Panel.URL) != "" {
				log.Info("no credential found; auto-enrolling with the provided one-time token before serving")
				if _, err := app.Enroll(cmd.Context(), cfg, log); err != nil {
					return err
				}
			}
			log.Info("mcpanel-node starting", "version", version.Version)
			return app.Serve(cmd.Context(), app.Options{Config: cfg, Log: log})
		},
	}
	serveCmd.Flags().String("data-dir", "", "override config dataDir")
	serveCmd.Flags().String("listen", "", "override config listen address")
	root.AddCommand(serveCmd)

	joinCmd := &cobra.Command{
		Use:   "join [panel-url]",
		Short: "One command to enroll and serve (token via --token, MCNODE_ENROLL_TOKEN, or interactive prompt)",
		Long: `Registers this node with the panel (unless already enrolled) and then runs
the control-channel server until interrupted — the whole "enroll + serve"
flow in one command, no config file required.

The panel URL comes from the positional argument, then panel.url in the
config file, then MCNODE_PANEL_URL. The one-time enroll token comes from
--token, then MCNODE_ENROLL_TOKEN / enroll.token, then an interactive stdin
prompt — stdin input never reaches shell history, so prefer the prompt or an
environment variable over --token.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			if len(args) == 1 {
				cfg.Panel.URL = strings.TrimRight(strings.TrimSpace(args[0]), "/")
			}
			log := logger(cfg)
			credStore := credential.NewStore(cfg.DataDir, cfg.Credential.Path)
			if credStore.Exists() {
				log.Info("credential already present; skipping enrollment")
			} else {
				if v, _ := cmd.Flags().GetString("token"); v != "" {
					cfg.Enroll.Token = strings.TrimSpace(v)
				}
				if strings.TrimSpace(cfg.Enroll.Token) == "" {
					token, readErr := readTokenLine()
					if readErr != nil {
						return readErr
					}
					cfg.Enroll.Token = token
				}
				if _, err := app.Enroll(cmd.Context(), cfg, log); err != nil {
					return err
				}
			}
			log.Info("mcpanel-node starting", "version", version.Version)
			return app.Serve(cmd.Context(), app.Options{Config: cfg, Log: log})
		},
	}
	joinCmd.Flags().String("data-dir", "", "override config dataDir")
	joinCmd.Flags().String("listen", "", "override config listen address")
	joinCmd.Flags().String("token", "", "one-time enroll token (prefer the interactive prompt or MCNODE_ENROLL_TOKEN to keep the token out of shell history)")
	root.AddCommand(joinCmd)

	fingerprintCmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Print the local TLS leaf certificate SHA-256 (pin this on the panel)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			hostname := cfg.TLS.Hostname
			if hostname == "" {
				hostname, _ = os.Hostname()
			}
			mgr := &certutil.Manager{
				DataDir:  cfg.DataDir,
				CertFile: cfg.TLS.CertFile,
				KeyFile:  cfg.TLS.KeyFile,
				Hostname: hostname,
			}
			fp, leaf, err := mgr.FingerprintPath()
			if err != nil {
				return err
			}
			fmt.Printf("sha256:%s\nsubject: %s\nnotAfter: %s\n",
				fp, leaf.Subject.String(), leaf.NotAfter.Format("2006-01-02T15:04:05Z07:00"))
			return nil
		},
	}
	fingerprintCmd.Flags().String("data-dir", "", "override config dataDir")
	root.AddCommand(fingerprintCmd)

	devCred := &cobra.Command{
		Use:   "dev-credential",
		Short: "TEST ONLY: create a local credential for integration testing without the panel",
		Long: `TEST ONLY — never run against production systems.

Creates credential.json locally so a panel implementation can dial the node
before bootstrap exists on either side. The nodeId is supplied manually (it
must match the panel-side node record); the secret is generated randomly and
printed to stdout exactly once — it is never logged by the structured logger
and never accepted as a CLI argument or written to the config file.
Production nodes obtain their credential exclusively through bootstrap.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig(cmd)
			if err != nil {
				return err
			}
			nodeID, _ := cmd.Flags().GetString("node-id")
			secret, err := generateSecret()
			if err != nil {
				return fmt.Errorf("generate secret: %w", err)
			}
			cred := credential.Credential{
				NodeID:       nodeID,
				NodeSecret:   secret,
				ControlPlan:  credential.ControlPlan{Mode: "direct"},
				EnrolledAtMs: time.Now().UnixMilli(),
			}
			store := credential.NewStore(cfg.DataDir, cfg.Credential.Path)
			if err := store.Save(cred); err != nil {
				return err
			}
			fmt.Printf("TEST ONLY credential written: %s\n", store.Path)
			fmt.Printf("nodeId: %s\n", nodeID)
			fmt.Printf("nodeSecret (copy now, shown once, never logged): %s\n", secret)
			return nil
		},
	}
	devCred.Flags().String("data-dir", "", "override config dataDir")
	devCred.Flags().String("node-id", "", "nodeId to embed (manual; must match the panel-side test record)")
	_ = devCred.MarkFlagRequired("node-id")
	root.AddCommand(devCred)

	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
