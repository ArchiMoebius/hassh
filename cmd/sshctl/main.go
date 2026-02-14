// cmd/sshctl/main.go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"
	"text/tabwriter"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"sshproxy/pkg/storage"
)

func main() {
	dbPath := flag.String("db", "ssh_connections.db", "SQLite database path")

	blockCmd := flag.NewFlagSet("block", flag.ExitOnError)
	blockHash := blockCmd.String("hassh", "", "HASSH fingerprint to block")
	blockReason := blockCmd.String("reason", "manual_block", "Reason for blocking")

	unblockCmd := flag.NewFlagSet("unblock", flag.ExitOnError)
	unblockHash := unblockCmd.String("hassh", "", "HASSH fingerprint to unblock")

	listCmd := flag.NewFlagSet("list", flag.ExitOnError)
	listIP := listCmd.String("ip", "", "Filter by IP address")
	listLimit := listCmd.Int("limit", 50, "Number of records to show")

	blockedCmd := flag.NewFlagSet("blocked", flag.ExitOnError)

	statsCmd := flag.NewFlagSet("stats", flag.ExitOnError)

	reloadCmd := flag.NewFlagSet("reload", flag.ExitOnError)
	reloadPID := reloadCmd.Int("pid", 0, "PID of proxy process to signal")

	if len(os.Args) < 2 {
		fmt.Println("Usage: sshctl [block|unblock|list|blocked|stats|reload]")
		os.Exit(1)
	}

	db, err := gorm.Open(sqlite.Open(*dbPath), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	repo, err := storage.NewRepository(db)
	if err != nil {
		log.Fatalf("Failed to initialize repository: %v", err)
	}

	switch os.Args[1] {
	case "block":
		blockCmd.Parse(os.Args[2:])
		if *blockHash == "" {
			log.Fatal("--hassh is required")
		}

		if err := repo.BlockHASH(*blockHash, *blockReason); err != nil {
			log.Fatalf("Failed to block HASSH: %v", err)
		}

		fmt.Printf("Blocked HASSH: %s\n", *blockHash)
		fmt.Printf("Reason: %s\n", *blockReason)
		fmt.Println("Run 'sshctl reload' to apply changes")

	case "unblock":
		unblockCmd.Parse(os.Args[2:])
		if *unblockHash == "" {
			log.Fatal("--hassh is required")
		}

		if err := repo.UnblockHASH(*unblockHash); err != nil {
			log.Fatalf("Failed to unblock HASSH: %v", err)
		}

		fmt.Printf("Unblocked HASSH: %s\n", *unblockHash)
		fmt.Println("Run 'sshctl reload' to apply changes")

	case "list":
		listCmd.Parse(os.Args[2:])

		var conns []storage.ConnectionDetail
		var err error

		if *listIP != "" {
			conns, err = repo.GetConnectionHistory(*listIP, *listLimit)
		} else {
			conns, err = repo.GetAllConnections(*listLimit)
		}

		if err != nil {
			log.Fatalf("Failed to list connections: %v", err)
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TIMESTAMP\tIP ADDRESS\tHASSH\tBANNER\tBLOCKED")

		for _, conn := range conns {
			blocked := "no"
			if conn.Blocked {
				blocked = "YES"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				conn.Timestamp.Format("2006-01-02 15:04:05"),
				conn.IPAddress,
				conn.HASSHFingerprint,
				conn.SSHClientBanner,
				blocked)
		}
		w.Flush()

	case "blocked":
		blockedCmd.Parse(os.Args[2:])

		fingerprints, err := repo.GetBlockedFingerprints()
		if err != nil {
			log.Fatalf("Failed to list blocked fingerprints: %v", err)
		}

		if len(fingerprints) == 0 {
			fmt.Println("No blocked fingerprints")
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "HASSH FINGERPRINT\tBLOCKED AT\tREASON")

		for _, fp := range fingerprints {
			fmt.Fprintf(w, "%s\t%s\t%s\n",
				fp.Fingerprint,
				fp.BlockedAt.Format("2006-01-02 15:04:05"),
				fp.Reason)
		}
		w.Flush()

	case "stats":
		statsCmd.Parse(os.Args[2:])

		stats, err := repo.GetStatistics()
		if err != nil {
			log.Fatalf("Failed to get statistics: %v", err)
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

	case "reload":
		reloadCmd.Parse(os.Args[2:])

		if *reloadPID == 0 {
			log.Fatal("--pid is required")
		}

		process, err := os.FindProcess(*reloadPID)
		if err != nil {
			log.Fatalf("Failed to find process: %v", err)
		}

		if err := process.Signal(syscall.SIGHUP); err != nil {
			log.Fatalf("Failed to send SIGHUP: %v", err)
		}

		fmt.Printf("Sent SIGHUP to process %d\n", *reloadPID)

	default:
		fmt.Println("Unknown command. Use: block, unblock, list, blocked, stats, or reload")
		os.Exit(1)
	}
}
