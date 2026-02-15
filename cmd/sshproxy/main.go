// cmd/sshproxy/main.go
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"sshproxy/pkg/proxy"
	"sshproxy/pkg/storage"
)

func main() {
	listenAddr := flag.String("listen", ":2222", "Proxy listen address")
	targetAddr := flag.String("target", "localhost:22", "Upstream SSH server")
	dbPath := flag.String("db", "ssh_connections.db", "SQLite database path")
	verbose := flag.Bool("v", false, "Verbose database logging")
	flag.Parse()

	// Initialize database
	dbConfig := &gorm.Config{}
	if *verbose {
		dbConfig.Logger = logger.Default.LogMode(logger.Info)
	} else {
		dbConfig.Logger = logger.Default.LogMode(logger.Warn)
	}

	db, err := gorm.Open(sqlite.Open(*dbPath), dbConfig)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	repo, err := storage.NewRepository(db)
	if err != nil {
		log.Fatalf("Failed to initialize repository: %v", err)
	}

	// Create proxy server
	server, err := proxy.NewServer(*listenAddr, *targetAddr, repo)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()

	log.Println("SSH Proxy with HASSH fingerprinting")
	log.Println("Send SIGHUP to reload blocklist from database")

	if err := server.Start(ctx); err != nil && err != context.Canceled {
		log.Printf("Server error: %v", err)
	}

	log.Println("Shutdown complete")
}
