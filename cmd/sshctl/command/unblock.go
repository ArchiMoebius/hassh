package command

import (
	"fmt"

	"sshproxy/pkg/storage"

	"github.com/spf13/cobra"
)

func NewUnblockCmd(repo *storage.Repository) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "unblock [hassh...]",
		Short: "Unblock HASSH fingerprints",
		Long:  `Remove one or more HASSH fingerprints from the blocklist.`,
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, hassh := range args {
				if err := repo.UnblockHASH(hassh); err != nil {
					return fmt.Errorf("failed to unblock %s: %w", hassh, err)
				}
				fmt.Printf("Unblocked HASSH: %s\n", hassh)
			}

			fmt.Println("\nRun 'sshctl reload' to apply changes to running proxy")
			return nil
		},
	}

	return cmd
}
