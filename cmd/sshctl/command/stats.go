package command

import (
	"fmt"

	"sshproxy/pkg/storage"

	"github.com/spf13/cobra"
)

func NewStatsCmd(repo *storage.Repository) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show connection statistics",
		Long:  `Display statistics about SSH connections.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			stats, err := repo.GetStatistics()
			if err != nil {
				return fmt.Errorf("failed to get statistics: %w", err)
			}

			fmt.Println("Connection Statistics:")
			fmt.Printf("  Total Connections:    %d\n", stats.TotalConnections)
			fmt.Printf("  Blocked Connections:  %d\n", stats.BlockedConnections)
			fmt.Printf("  Unique IP Addresses:  %d\n", stats.UniqueIPs)
			fmt.Printf("  Unique Fingerprints:  %d\n", stats.UniqueFingerprints)
			fmt.Printf("  Unique Banners:       %d\n", stats.UniqueBanners)

			if stats.TotalConnections > 0 {
				blockRate := float64(stats.BlockedConnections) / float64(stats.TotalConnections) * 100
				fmt.Printf("  Block Rate:           %.2f%%\n", blockRate)
			}

			return nil
		},
	}

	return cmd
}
