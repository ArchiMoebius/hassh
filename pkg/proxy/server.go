// pkg/proxy/server.go
package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

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
	syslog      *SyslogWriter
	reloadChan  chan os.Signal
	connCounter atomic.Uint64
	activeConns sync.WaitGroup
}

// NewServer creates a proxy server
func NewServer(listenAddr, targetAddr string, repo *storage.Repository) (*Server, error) {
	server := &Server{
		listenAddr: listenAddr,
		targetAddr: targetAddr,
		repo:       repo,
		reloadChan: make(chan os.Signal, 1),
	}

	// Initialize syslog (optional, continues if unavailable)
	syslogWriter, err := NewSyslogWriter()
	if err != nil {
		log.Printf("Warning: Failed to initialize syslog: %v", err)
		log.Println("Continuing without syslog support")
	} else {
		server.syslog = syslogWriter
		log.Println("Syslog initialized - writing to auth.log")
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

// acceptWithContext wraps Accept() to respect context cancellation
func acceptWithContext(ctx context.Context, listener net.Listener) (net.Conn, error) {
	type deadliner interface {
		SetDeadline(time.Time) error
	}

	if dl, ok := listener.(deadliner); ok {
		dl.SetDeadline(time.Now().Add(1 * time.Second))
		defer dl.SetDeadline(time.Time{})
	}

	connChan := make(chan net.Conn, 1)
	errChan := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}
		connChan <- conn
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case conn := <-connChan:
		return conn, nil
	case err := <-errChan:
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				return nil, err
			}
		}
		return nil, err
	}
}

// Start begins accepting connections
func (s *Server) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	defer listener.Close()

	if s.syslog != nil {
		defer s.syslog.Close()
	}

	log.Printf("SSH proxy listening on %s -> %s", s.listenAddr, s.targetAddr)

	// Background reload handler
	go s.handleReloads(ctx)

	// Accept loop with context awareness
	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down, waiting for active connections to close...")
			s.activeConns.Wait()
			return ctx.Err()
		default:
		}

		conn, err := acceptWithContext(ctx, listener)
		if err != nil {
			if ctx.Err() != nil {
				s.activeConns.Wait()
				return ctx.Err()
			}

			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			log.Printf("Accept error: %v", err)
			continue
		}

		s.activeConns.Add(1)
		go func() {
			defer s.activeConns.Done()
			s.handleConnection(conn)
		}()
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

	clientAddr := clientConn.RemoteAddr().(*net.TCPAddr)
	clientIP := clientAddr.IP.String()
	clientPort := clientAddr.Port

	localAddr := clientConn.LocalAddr().(*net.TCPAddr)
	proxyIP := localAddr.IP.String()
	proxyPort := localAddr.Port

	// Track upstream connection info and username
	var upstreamLocalIP string
	var upstreamLocalPort int
	var username string

	// Ensure we always log disconnect with full chain
	defer func() {
		if s.syslog != nil && upstreamLocalIP != "" {
			s.syslog.LogDisconnect(connID, clientIP, clientPort, proxyIP, proxyPort, upstreamLocalIP, upstreamLocalPort, s.targetAddr, username)
		}
		if upstreamLocalIP != "" {
			log.Printf("[conn:%d] Disconnected from %s port %d -> %s port %d -> %s port %d -> %s",
				connID, clientIP, clientPort, proxyIP, proxyPort, upstreamLocalIP, upstreamLocalPort, s.targetAddr)
		} else {
			log.Printf("[conn:%d] Disconnected from %s port %d -> %s port %d -> %s",
				connID, clientIP, clientPort, proxyIP, proxyPort, s.targetAddr)
		}
	}()

	// Connect to upstream SSH server first to get the local port
	upstreamConn, err := net.Dial("tcp", s.targetAddr)
	if err != nil {
		log.Printf("[conn:%d] Failed to connect to upstream: %v", connID, err)
		if s.syslog != nil {
			s.syslog.LogError(connID, clientIP, fmt.Sprintf("Failed to connect to upstream %s: %v", s.targetAddr, err))
		}
		return
	}
	defer upstreamConn.Close()

	// Get the actual local address used for upstream connection
	upstreamLocalAddr := upstreamConn.LocalAddr().(*net.TCPAddr)
	upstreamLocalIP = upstreamLocalAddr.IP.String()
	upstreamLocalPort = upstreamLocalAddr.Port

	upstreamRemoteAddr := upstreamConn.RemoteAddr().String()

	// Wrap connection to intercept handshake
	wrappedConn := NewSSHConn(clientConn, func(fp *hassh.Fingerprint) bool {
		blocked := s.blocklist.Contains(fp.Hash)

		// Log to syslog with full chain including upstream port
		if s.syslog != nil {
			s.syslog.LogConnection(connID, clientIP, clientPort, proxyIP, proxyPort, upstreamLocalIP, upstreamLocalPort, s.targetAddr, blocked)
			s.syslog.LogHandshake(connID, clientIP, clientPort, proxyIP, proxyPort, upstreamLocalIP, upstreamLocalPort, s.targetAddr, fp.Hash, fp.ClientBanner)
		}

		// Record in database (async to avoid blocking)
		go func() {
			if err := s.repo.RecordConnection(clientIP, fp.Hash, fp.ClientBanner, blocked); err != nil {
				log.Printf("[conn:%d] Failed to record connection: %v", connID, err)
			}
		}()

		if blocked {
			log.Printf("[conn:%d] BLOCKED: %s port %d -> %s port %d -> %s port %d -> %s (HASSH: %s, Banner: %s)",
				connID, clientIP, clientPort, proxyIP, proxyPort, upstreamLocalIP, upstreamLocalPort, s.targetAddr, fp.Hash, fp.ClientBanner)
			return true
		}

		log.Printf("[conn:%d] ALLOWED: %s port %d -> %s port %d -> %s port %d -> %s (HASSH: %s, Banner: %s)",
			connID, clientIP, clientPort, proxyIP, proxyPort, upstreamLocalIP, upstreamLocalPort, s.targetAddr, fp.Hash, fp.ClientBanner)
		return false
	})

	log.Printf("[conn:%d] Proxying: %s port %d -> %s port %d -> %s port %d -> %s",
		connID, clientIP, clientPort, proxyIP, proxyPort, upstreamLocalIP, upstreamLocalPort, upstreamRemoteAddr)

	// Bidirectional copy with proper cleanup
	done := make(chan error, 2)

	go func() {
		_, err := io.Copy(upstreamConn, wrappedConn)
		if tcpConn, ok := upstreamConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		done <- err
	}()

	go func() {
		_, err := io.Copy(wrappedConn, upstreamConn)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
		done <- err
	}()

	// Wait for both directions to complete
	<-done
	<-done
}
