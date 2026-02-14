package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"sshproxy/pkg/filter"
	"sshproxy/pkg/hassh"
	"sshproxy/pkg/storage"
)

// Server is a transparent SSH proxy with HASSH fingerprinting
type Server struct {
	listenAddr  string
	targetAddr  string
	repo        *storage.Repository
	blocklist   *filter.BlocklistFilter
	reloadChan  chan os.Signal
	connCounter atomic.Uint64
}

// NewServer creates a proxy server
func NewServer(listenAddr, targetAddr string, repo *storage.Repository) (*Server, error) {
	server := &Server{
		listenAddr: listenAddr,
		targetAddr: targetAddr,
		repo:       repo,
		reloadChan: make(chan os.Signal, 1),
	}

	// Initial blocklist load
	if err := server.reloadBlocklist(); err != nil {
		return nil, fmt.Errorf("failed to load initial blocklist: %w", err)
	}

	// Setup SIGHUP handler for reload
	signal.Notify(server.reloadChan, syscall.SIGHUP)

	return server, nil
}

// reloadBlocklist loads blocked HASSH values from database into bloom filter
func (s *Server) reloadBlocklist() error {
	log.Println("Loading blocklist from database...")

	blockedHashes, err := s.repo.LoadBlockedHashes()
	if err != nil {
		return err
	}

	// Create or reload filter
	if s.blocklist == nil {
		expectedSize := uint(len(blockedHashes))
		if expectedSize < 1000 {
			expectedSize = 1000 // Minimum size
		}
		s.blocklist = filter.NewBlocklistFilter(expectedSize, 0.01)
	}

	s.blocklist.Reload(blockedHashes)

	log.Printf("Blocklist loaded: %d unique HASSH fingerprints", s.blocklist.Count())
	return nil
}

// Start begins accepting connections
func (s *Server) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()

	log.Printf("SSH proxy listening on %s -> %s", s.listenAddr, s.targetAddr)

	// Background reload handler
	go s.handleReloads(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					log.Printf("Accept error: %v", err)
					continue
				}
			}

			go s.handleConnection(conn)
		}
	}
}

// handleReloads listens for SIGHUP and reloads blocklist
func (s *Server) handleReloads(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.reloadChan:
			log.Println("Received SIGHUP, reloading blocklist...")
			if err := s.reloadBlocklist(); err != nil {
				log.Printf("Failed to reload blocklist: %v", err)
			} else {
				log.Println("Blocklist reload complete")
			}
		}
	}
}

// handleConnection processes a single SSH connection
func (s *Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	connID := s.connCounter.Add(1)
	clientIP := clientConn.RemoteAddr().(*net.TCPAddr).IP.String()

	// Wrap connection to intercept handshake
	wrappedConn := NewSSHConn(clientConn, func(fp *hassh.Fingerprint) bool {
		// O(k) bloom filter lookup where k is typically 3-5 hash functions
		blocked := s.blocklist.Contains(fp.Hash)

		// Record in database (async to avoid blocking)
		go func() {
			if err := s.repo.RecordConnection(clientIP, fp.Hash, fp.ClientBanner, blocked); err != nil {
				log.Printf("[conn:%d] Failed to record connection: %v", connID, err)
			}
		}()

		if blocked {
			log.Printf("[conn:%d] BLOCKED: %s (HASSH: %s, Banner: %s)",
				connID, clientIP, fp.Hash, fp.ClientBanner)
			return true
		}

		log.Printf("[conn:%d] ALLOWED: %s (HASSH: %s, Banner: %s)",
			connID, clientIP, fp.Hash, fp.ClientBanner)
		return false
	})

	// Connect to upstream SSH server
	upstreamConn, err := net.Dial("tcp", s.targetAddr)
	if err != nil {
		log.Printf("[conn:%d] Failed to connect to upstream: %v", connID, err)
		return
	}
	defer upstreamConn.Close()

	log.Printf("[conn:%d] Proxying %s -> %s", connID, clientIP, s.targetAddr)

	// Bidirectional copy
	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(upstreamConn, wrappedConn)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(wrappedConn, upstreamConn)
		errChan <- err
	}()

	// Wait for either direction to complete
	err = <-errChan
	if err != nil && err != io.EOF {
		log.Printf("[conn:%d] Proxy error: %v", connID, err)
	}
}
