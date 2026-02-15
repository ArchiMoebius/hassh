package command

import (
	"fmt"

	"sshproxy/pkg/storage"

	"github.com/spf13/cobra"
)

func NewBlockCmd(repo *storage.Repository) *cobra.Command {
	var reason string

	cmd := &cobra.Command{
		Use:   "block [hassh...]",
		Short: "Block HASSH fingerprints",
		Long:  `Add one or more HASSH fingerprints to the blocklist.`,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, hassh := range args {
				if err := repo.BlockHASH(hassh, reason); err != nil {
					return fmt.Errorf("failed to block %s: %w", hassh, err)
				}
				fmt.Printf("Blocked HASSH: %s\n", hassh)
			}

			fmt.Println("\nRun 'sshctl reload' to apply changes to running proxy")
			return nil
		},
	}

	cmd.Flags().StringVar(&reason, "reason", "manual_block", "Reason for blocking")

	return cmd
}
