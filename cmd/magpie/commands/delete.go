package commands

import (
	"fmt"
	"strings"

	"github.com/ezequielcamezzana/magpie/internal/server/config"
	"github.com/ezequielcamezzana/magpie/internal/server/db"
	"github.com/ezequielcamezzana/magpie/internal/server/purl"

	"github.com/spf13/cobra"
)

// NewDeleteCmd removes a component and its package-specific cached data from the
// store. Destructive and local-only (no public surface): the operator runs it on
// the box. Shared caches (NVD per-CPE/per-CVE records, dedup'd vuln headers) are
// left intact — see Store.DeleteComponent.
func NewDeleteCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "delete <purl>",
		Short: "Delete a component and its cached data (cpes, vulns) by purl",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			p, err := purl.Parse(args[0])
			if err != nil {
				return fmt.Errorf("parse purl %q: %w", args[0], err)
			}
			spurl := purl.Strip(p)
			osvKey := purl.Decompose(p).OSVQuery().StoreKey()

			database, err := db.Open(cfg.DBPath)
			if err != nil {
				return fmt.Errorf("open store %q: %w", cfg.DBPath, err)
			}
			defer database.Close()

			if !yes {
				fmt.Printf("Delete %s and its cached data from %s? [y/N]: ", spurl, cfg.DBPath)
				var answer string
				fmt.Scanln(&answer)
				if strings.ToLower(strings.TrimSpace(answer)) != "y" {
					fmt.Println("aborted")
					return nil
				}
			}

			r, err := database.DeleteComponent(cmd.Context(), spurl, osvKey)
			if err != nil {
				return fmt.Errorf("delete: %w", err)
			}
			fmt.Printf("deleted %s — component=%d cpes=%d missed=%d eco_vulns=%d osv_vulns=%d\n",
				spurl, r.Component, r.CPEs, r.MissedCPE, r.EcoVulns, r.OSVVulns)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	return cmd
}
