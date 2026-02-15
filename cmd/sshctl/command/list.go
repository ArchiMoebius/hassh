package command

import (
	"fmt"
	"os"
	"text/tabwriter"

	"sshproxy/pkg/storage"

	"github.com/spf13/cobra"
)

func NewListCmd(repo *storage.Repository) *cobra.Command {
	var (
		limit   int
		state   string
		sortBy  string
		reverse bool
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List HASSH fingerprints with statistics",
		Long:  `List unique HASSH fingerprints with IP counts and last seen timestamps.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var blocked *bool
			switch state {
			case "allowed":
				b := false
				blocked = &b
			case "blocked":
				b := true
				blocked = &b
			case "all":
				blocked = nil
			default:
				return fmt.Errorf("invalid state: %s (must be: allowed, blocked, all)", state)
			}

			summaries, err := repo.ListHASSHSummaries(limit, blocked, sortBy, reverse)
			if err != nil {
				return fmt.Errorf("failed to list fingerprints: %w", err)
			}

			if len(summaries) == 0 {
				fmt.Println("No fingerprints found")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			_, _ = fmt.Fprintln(w, "HASSH\tBANNER\tIPs\tCONNS\tLAST SEEN\tBLOCKED")

			for _, s := range summaries {
				blocked := "no"
				if s.Blocked {
					blocked = "YES"
				}

				// Truncate banner if too long
				banner := s.SSHClientBanner
				if len(banner) > 45 {
					banner = banner[:42] + "..."
				}

				_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n",
					s.HASSHFingerprint,
					banner,
					s.IPCount,
					s.TotalConnections,
					s.LastSeen.Format("2006-01-02 15:04:05"),
					blocked)
			}
			err = w.Flush()
			if err != nil {
				return fmt.Errorf("failed to flush: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().IntVarP(&limit, "limit", "n", 25, "Number of records to show")
	cmd.Flags().StringVarP(&state, "state", "s", "all", "Filter by state: allowed, blocked, all")
	cmd.Flags().StringVar(&sortBy, "sort", "last_seen", "Sort by: last_seen, ip_count, total, hassh, banner")
	cmd.Flags().BoolVarP(&reverse, "reverse", "r", false, "Reverse sort order")

	return cmd
}
