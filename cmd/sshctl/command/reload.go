package command

import (
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"
)

func NewReloadCmd() *cobra.Command {
	var pid int

	cmd := &cobra.Command{
		Use:   "reload",
		Short: "Reload proxy blocklist",
		Long:  `Send SIGHUP to proxy process to reload blocklist from database.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if pid == 0 {
				return fmt.Errorf("--pid is required")
			}

			process, err := os.FindProcess(pid)
			if err != nil {
				return fmt.Errorf("failed to find process: %w", err)
			}

			if err := process.Signal(syscall.SIGHUP); err != nil {
				return fmt.Errorf("failed to send SIGHUP: %w", err)
			}

			fmt.Printf("Sent SIGHUP to process %d\n", pid)
			return nil
		},
	}

	cmd.Flags().IntVar(&pid, "pid", 0, "PID of proxy process to signal")
	err := cmd.MarkFlagRequired("pid")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return cmd
}
