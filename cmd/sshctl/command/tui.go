package command

import (
	"sshproxy/cmd/sshctl/tui"
	"sshproxy/pkg/storage"

	"github.com/spf13/cobra"
)

func NewTUICmd(repo *storage.Repository) *cobra.Command {
	var limit int

	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Start interactive TUI",
		Long:  `Launch an interactive terminal user interface for managing connections.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return tui.Run(repo, limit)
		},
	}

	cmd.Flags().IntVarP(&limit, "limit", "n", 25, "Number of connections to display per page")

	return cmd
}
