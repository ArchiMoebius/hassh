package hassh

import (
	"crypto/md5" // #nosec G401 -- MD5 used for fingerprinting only
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// maxNameListLength prevents DoS via excessive memory allocation
	// SSH name-lists should be reasonable in size (typical: <1KB)
	maxNameListLength = 1024 * 1024 // 1MB safety limit

	// SSH_MSG_KEXINIT message type
	sshMsgKexInit = 20
)

// Fingerprint represents a HASSH fingerprint with client metadata
type Fingerprint struct {
	Hash         string
	ClientBanner string
	RemoteAddr   string
}

// Calculate generates HASSH fingerprint from SSH key exchange algorithms
func Calculate(kex, ciphers, macs, compression []string) string {
	algorithms := fmt.Sprintf("%s;%s;%s;%s",
		strings.Join(kex, ","),
		strings.Join(ciphers, ","),
		strings.Join(macs, ","),
		strings.Join(compression, ","))

	hash := md5.Sum([]byte(algorithms)) // #nosec G401
	return hex.EncodeToString(hash[:])
}

// parseNameList extracts SSH name-list from wire format
func parseNameList(data []byte, offset int) ([]string, int, error) {
	// Check if we have enough bytes to read the length field
	if offset+4 > len(data) {
		return nil, offset, fmt.Errorf("buffer too short for name-list length")
	}

	length := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// Validate length before any conversion or arithmetic to prevent:
	// 1. Integer overflow on 32-bit systems when converting uint32 to int
	// 2. DoS via excessive memory allocation
	// 3. Integer overflow in offset+length calculation
	if length > maxNameListLength {
		return nil, offset, fmt.Errorf("name-list too large: %d bytes (max: %d)", length, maxNameListLength)
	}

	// Safe to convert to int now - length is <= 1MB
	listLen := int(length)

	// Check if we have enough remaining data
	// Using subtraction to avoid potential overflow in offset+listLen
	if offset > len(data)-listLen {
		return nil, offset, fmt.Errorf("buffer too short for name-list data: need %d bytes, have %d", listLen, len(data)-offset)
	}

	// Handle empty name-list
	if length == 0 {
		return []string{}, offset, nil
	}

	// Extract name-list string
	nameList := string(data[offset : offset+listLen])
	offset += listLen

	// Split into individual algorithm names
	names := strings.Split(nameList, ",")

	return names, offset, nil
}

// ParseKexInit extracts algorithm lists from SSH_MSG_KEXINIT (RFC 4253 §7.1)
//
// RFC 4253 Section 7.1 specifies the complete packet structure:
//   byte         SSH_MSG_KEXINIT (20)
//   byte[16]     cookie (random bytes)
//   name-list    kex_algorithms
//   name-list    server_host_key_algorithms
//   name-list    encryption_algorithms_client_to_server
//   name-list    encryption_algorithms_server_to_client
//   name-list    mac_algorithms_client_to_server
//   name-list    mac_algorithms_server_to_client
//   name-list    compression_algorithms_client_to_server
//   name-list    compression_algorithms_server_to_client
//   name-list    languages_client_to_server
//   name-list    languages_server_to_client
//   boolean      first_kex_packet_follows
//   uint32       0 (reserved for future extension)
func ParseKexInit(payload []byte) (kex, ciphers, macs, compression []string, err error) {
	// Validate minimum packet size: 1 byte (msg type) + 16 bytes (cookie)
	if len(payload) < 17 {
		return nil, nil, nil, nil, fmt.Errorf("invalid KEXINIT packet: too short (%d bytes)", len(payload))
	}

	// Verify message type
	if payload[0] != sshMsgKexInit {
		return nil, nil, nil, nil, fmt.Errorf("invalid KEXINIT packet: wrong message type (got %d, expected %d)", payload[0], sshMsgKexInit)
	}

	// Skip message type (1) + cookie (16)
	offset := 17

	// Parse kex_algorithms (client preference)
	if kex, offset, err = parseNameList(payload, offset); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse kex_algorithms: %w", err)
	}

	// Skip server_host_key_algorithms
	if _, offset, err = parseNameList(payload, offset); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse server_host_key_algorithms: %w", err)
	}

	// Parse encryption_algorithms_client_to_server
	if ciphers, offset, err = parseNameList(payload, offset); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse encryption_algorithms_client_to_server: %w", err)
	}

	// Skip encryption_algorithms_server_to_client
	if _, offset, err = parseNameList(payload, offset); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse encryption_algorithms_server_to_client: %w", err)
	}

	// Parse mac_algorithms_client_to_server
	if macs, offset, err = parseNameList(payload, offset); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse mac_algorithms_client_to_server: %w", err)
	}

	// Skip mac_algorithms_server_to_client
	if _, offset, err = parseNameList(payload, offset); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse mac_algorithms_server_to_client: %w", err)
	}

	// Parse compression_algorithms_client_to_server
	if compression, offset, err = parseNameList(payload, offset); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse compression_algorithms_client_to_server: %w", err)
	}

	// Skip compression_algorithms_server_to_client (RFC compliance)
	if _, offset, err = parseNameList(payload, offset); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse compression_algorithms_server_to_client: %w", err)
	}

	// Skip languages_client_to_server (RFC compliance)
	if _, offset, err = parseNameList(payload, offset); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse languages_client_to_server: %w", err)
	}

	// Skip languages_server_to_client (RFC compliance)
	if _, offset, err = parseNameList(payload, offset); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to parse languages_server_to_client: %w", err)
	}

	// Skip first_kex_packet_follows (boolean - 1 byte)
	if offset+1 > len(payload) {
		return nil, nil, nil, nil, fmt.Errorf("buffer too short for first_kex_packet_follows")
	}
	offset++

	// Skip reserved field (uint32 - 4 bytes)
	if offset+4 > len(payload) {
		return nil, nil, nil, nil, fmt.Errorf("buffer too short for reserved field")
	}
	// Don't need to advance offset since we're done parsing

	return kex, ciphers, macs, compression, nil
}
