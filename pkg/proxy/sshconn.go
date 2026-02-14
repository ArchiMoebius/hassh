package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"

	"sshproxy/pkg/hassh"
)

const (
	maxPacketSize = 35000
	sshMsgKexInit = 20
)

// SSHConn wraps a connection to intercept SSH handshake
type SSHConn struct {
	net.Conn
	onHandshake  func(*hassh.Fingerprint) bool
	buf          []byte
	versionRead  bool
	captured     bool
	clientBanner string
}

// NewSSHConn creates a wrapped connection with handshake callback
// Callback returns true to block the connection
func NewSSHConn(conn net.Conn, onHandshake func(*hassh.Fingerprint) bool) *SSHConn {
	return &SSHConn{
		Conn:        conn,
		onHandshake: onHandshake,
		buf:         make([]byte, 0, 4096),
	}
}

func (c *SSHConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)

	if n > 0 && !c.captured {
		c.buf = append(c.buf, b[:n]...)
		if c.tryParseHandshake() {
			// Connection blocked by callback
			return 0, io.EOF
		}
	}

	return n, err
}

// tryParseHandshake attempts to extract HASSH from buffered data
func (c *SSHConn) tryParseHandshake() bool {
	// Step 1: Parse SSH version banner
	if !c.versionRead {
		if idx := bytes.Index(c.buf, []byte("SSH-")); idx >= 0 {
			if end := bytes.Index(c.buf[idx:], []byte("\r\n")); end > 0 {
				c.clientBanner = string(c.buf[idx : idx+end])
				c.versionRead = true
				c.buf = c.buf[idx+end+2:]
			}
		}
	}

	// Step 2: Parse binary packet for KEXINIT
	if c.versionRead && !c.captured && len(c.buf) >= 5 {
		packetLen := binary.BigEndian.Uint32(c.buf[0:4])

		// Validate packet length
		if packetLen < 1 || packetLen > maxPacketSize || len(c.buf) < int(4+packetLen) {
			return false
		}

		paddingLen := int(c.buf[4])
		payloadLen := int(packetLen) - paddingLen - 1

		if payloadLen <= 0 || 5+payloadLen > len(c.buf) {
			return false
		}

		payload := c.buf[5 : 5+payloadLen]

		// Check for SSH_MSG_KEXINIT
		if len(payload) > 0 && payload[0] == sshMsgKexInit {
			kex, ciphers, macs, compression, err := hassh.ParseKexInit(payload)
			if err != nil {
				return false
			}

			fingerprint := &hassh.Fingerprint{
				Hash:         hassh.Calculate(kex, ciphers, macs, compression),
				ClientBanner: c.clientBanner,
				RemoteAddr:   c.Conn.RemoteAddr().String(),
			}

			c.captured = true

			if c.onHandshake != nil {
				return c.onHandshake(fingerprint)
			}
		}
	}

	return false
}
