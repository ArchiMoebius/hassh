package proxy

import (
	"fmt"
	"log/syslog"
)

// SyslogWriter wraps syslog for SSH proxy event logging
type SyslogWriter struct {
	writer *syslog.Writer
}

// NewSyslogWriter creates a syslog writer for SSH proxy events
func NewSyslogWriter() (*SyslogWriter, error) {
	w, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_INFO, "sshproxy")
	if err != nil {
		return nil, err
	}
	return &SyslogWriter{writer: w}, nil
}

// LogConnection logs a connection event with full provenance chain
func (s *SyslogWriter) LogConnection(connID uint64, clientIP string, clientPort int, proxyIP string, proxyPort int, upstreamLocalIP string, upstreamLocalPort int, targetAddr string, blocked bool) error {
	if s.writer == nil {
		return fmt.Errorf("syslog writer not initialized")
	}

	status := "ALLOWED"
	if blocked {
		status = "BLOCKED"
	}

	// Format: Connection [ALLOWED/BLOCKED]: CLIENT_IP port CLIENT_PORT -> PROXY_IP port PROXY_PORT -> UPSTREAM_LOCAL_IP port UPSTREAM_LOCAL_PORT -> TARGET
	msg := fmt.Sprintf("[conn:%d] Connection %s: %s port %d -> %s port %d -> %s port %d -> %s",
		connID, status, clientIP, clientPort, proxyIP, proxyPort, upstreamLocalIP, upstreamLocalPort, targetAddr)

	if blocked {
		return s.writer.Warning(msg)
	}
	return s.writer.Info(msg)
}

// LogHandshake logs HASSH fingerprint details with full chain
func (s *SyslogWriter) LogHandshake(connID uint64, clientIP string, clientPort int, proxyIP string, proxyPort int, upstreamLocalIP string, upstreamLocalPort int, targetAddr string, hassh, banner string) error {
	if s.writer == nil {
		return fmt.Errorf("syslog writer not initialized")
	}

	msg := fmt.Sprintf("[conn:%d] Client %s port %d -> %s port %d -> %s port %d -> %s: HASSH=%s Banner=%s",
		connID, clientIP, clientPort, proxyIP, proxyPort, upstreamLocalIP, upstreamLocalPort, targetAddr, hassh, banner)

	return s.writer.Info(msg)
}

// LogDisconnect logs connection termination in sshd-compatible format
func (s *SyslogWriter) LogDisconnect(connID uint64, clientIP string, clientPort int, proxyIP string, proxyPort int, upstreamLocalIP string, upstreamLocalPort int, targetAddr string, username string) error {
	if s.writer == nil {
		return fmt.Errorf("syslog writer not initialized")
	}

	// Format: Disconnected from [user USER] CLIENT_IP port CLIENT_PORT -> PROXY_IP port PROXY_PORT -> UPSTREAM_LOCAL_IP port UPSTREAM_LOCAL_PORT -> TARGET
	var msg string
	if username != "" {
		msg = fmt.Sprintf("[conn:%d] Disconnected from user %s %s port %d -> %s port %d -> %s port %d -> %s",
			connID, username, clientIP, clientPort, proxyIP, proxyPort, upstreamLocalIP, upstreamLocalPort, targetAddr)
	} else {
		msg = fmt.Sprintf("[conn:%d] Disconnected from %s port %d -> %s port %d -> %s port %d -> %s",
			connID, clientIP, clientPort, proxyIP, proxyPort, upstreamLocalIP, upstreamLocalPort, targetAddr)
	}

	return s.writer.Info(msg)
}

// LogError logs connection errors
func (s *SyslogWriter) LogError(connID uint64, clientIP string, errMsg string) error {
	if s.writer == nil {
		return fmt.Errorf("syslog writer not initialized")
	}

	msg := fmt.Sprintf("[conn:%d] Error for %s: %s", connID, clientIP, errMsg)
	return s.writer.Err(msg)
}

// Close closes the syslog connection
func (s *SyslogWriter) Close() error {
	if s.writer != nil {
		return s.writer.Close()
	}
	return nil
}
