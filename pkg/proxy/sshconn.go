// pkg/proxy/sshconn.go
package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"

	"sshproxy/pkg/hassh"
)

const (
	maxPacketSize  = 35000
	sshMsgKexInit  = 20
	maxCaptureSize = 8192
)

// SSHConn wraps a connection to intercept SSH handshake
type SSHConn struct {
	net.Conn
	onHandshake func(*hassh.Fingerprint) bool
	captureBuf  *bytes.Buffer
	captured    bool
	blocked     bool
}

// NewSSHConn creates a wrapped connection with handshake callback
func NewSSHConn(conn net.Conn, onHandshake func(*hassh.Fingerprint) bool) *SSHConn {
	return &SSHConn{
		Conn:        conn,
		onHandshake: onHandshake,
		captureBuf:  bytes.NewBuffer(make([]byte, 0, maxCaptureSize)),
	}
}

// Read wraps the underlying read to capture handshake data
func (c *SSHConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)

	// Capture data for HASSH analysis (but don't consume it)
	if n > 0 && !c.captured && c.captureBuf.Len() < maxCaptureSize {
		c.captureBuf.Write(b[:n])

		// Try to parse what we have so far
		if c.tryParseHandshake() {
			c.captured = true

			// If blocked, close the connection
			if c.blocked {
				return n, io.EOF
			}
		}
	}

	return n, err
}

// tryParseHandshake attempts to extract HASSH from captured data
func (c *SSHConn) tryParseHandshake() bool {
	buf := c.captureBuf.Bytes()

	// Need minimum data
	if len(buf) < 10 {
		return false
	}

	// Step 1: Find and parse SSH version banner
	idx := bytes.Index(buf, []byte("SSH-"))
	if idx == -1 {
		return false
	}

	endIdx := bytes.Index(buf[idx:], []byte("\r\n"))
	if endIdx == -1 {
		return false // Need more data for complete banner
	}

	clientBanner := string(buf[idx : idx+endIdx])
	bannerEnd := idx + endIdx + 2

	// Step 2: Parse binary SSH packet
	if len(buf) < bannerEnd+5 {
		return false // Need at least packet length field
	}

	packetBuf := buf[bannerEnd:]
	packetLen := binary.BigEndian.Uint32(packetBuf[0:4])

	// Validate packet length
	if packetLen < 1 || packetLen > maxPacketSize {
		return false
	}

	totalPacketLen := 4 + int(packetLen)
	if len(packetBuf) < totalPacketLen {
		return false // Need complete packet
	}

	paddingLen := int(packetBuf[4])
	payloadLen := int(packetLen) - paddingLen - 1

	if payloadLen <= 0 || 5+payloadLen > len(packetBuf) {
		return false
	}

	payload := packetBuf[5 : 5+payloadLen]

	// Check for SSH_MSG_KEXINIT
	if len(payload) == 0 || payload[0] != sshMsgKexInit {
		return false
	}

	// Parse KEXINIT
	kex, ciphers, macs, compression, err := hassh.ParseKexInit(payload)
	if err != nil {
		return false
	}

	// We have everything we need!
	fingerprint := &hassh.Fingerprint{
		Hash:         hassh.Calculate(kex, ciphers, macs, compression),
		ClientBanner: clientBanner,
		RemoteAddr:   c.Conn.RemoteAddr().String(),
	}

	if c.onHandshake != nil {
		c.blocked = c.onHandshake(fingerprint)
	}

	return true
}
