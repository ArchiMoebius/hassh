package command

import (
	"fmt"
	"os"
	"text/tabwriter"

	"sshproxy/pkg/storage"

	"github.com/spf13/cobra"
)

func NewLogCmd(repo *storage.Repository) *cobra.Command {
	var (
		limit   int
		state   string
		sortBy  string
		reverse bool
	)

	cmd := &cobra.Command{
		Use:   "log",
		Short: "Show connection log",
		Long:  `Show individual connection events with full details.`,
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

			connections, err := repo.ListConnections(limit, blocked, sortBy, reverse)
			if err != nil {
				return fmt.Errorf("failed to list connections: %w", err)
			}

			if len(connections) == 0 {
				fmt.Println("No connections found")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "ID\tTIMESTAMP\tIP ADDRESS\tHASSH\tBANNER\tBLOCKED")

			for _, conn := range connections {
				blocked := "no"
				if conn.Blocked {
					blocked = "YES"
				}

				// Truncate banner if too long
				banner := conn.SSHClientBanner
				if len(banner) > 40 {
					banner = banner[:37] + "..."
				}

				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n",
					conn.ID,
					conn.Timestamp.Format("2006-01-02 15:04:05"),
					conn.IPAddress,
					conn.HASSHFingerprint,
					banner,
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
	cmd.Flags().StringVar(&sortBy, "sort", "timestamp", "Sort by: timestamp, ip, hassh")
	cmd.Flags().BoolVarP(&reverse, "reverse", "r", false, "Reverse sort order")

	return cmd
}
