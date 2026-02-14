package hassh

import (
	"crypto/md5" // #nosec G401 -- MD5 used for fingerprinting only
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
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
	if offset+4 > len(data) {
		return nil, offset, fmt.Errorf("buffer too short for name-list length")
	}

	length := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if offset+int(length) > len(data) {
		return nil, offset, fmt.Errorf("buffer too short for name-list data")
	}

	if length == 0 {
		return []string{}, offset, nil
	}

	nameList := string(data[offset : offset+int(length)])
	offset += int(length)

	return strings.Split(nameList, ","), offset, nil
}

// ParseKexInit extracts algorithm lists from SSH_MSG_KEXINIT (RFC 4253 §7.1)
func ParseKexInit(payload []byte) (kex, ciphers, macs, compression []string, err error) {
	if len(payload) < 17 || payload[0] != 20 {
		return nil, nil, nil, nil, fmt.Errorf("invalid KEXINIT packet")
	}

	// Skip message type (1) + cookie (16)
	offset := 17

	// Parse required name-lists
	if kex, offset, err = parseNameList(payload, offset); err != nil {
		return
	}

	// Skip server_host_key_algorithms
	if _, offset, err = parseNameList(payload, offset); err != nil {
		return
	}

	// encryption_algorithms_client_to_server
	if ciphers, offset, err = parseNameList(payload, offset); err != nil {
		return
	}

	// Skip encryption_algorithms_server_to_client
	if _, offset, err = parseNameList(payload, offset); err != nil {
		return
	}

	// mac_algorithms_client_to_server
	if macs, offset, err = parseNameList(payload, offset); err != nil {
		return
	}

	// Skip mac_algorithms_server_to_client
	if _, offset, err = parseNameList(payload, offset); err != nil {
		return
	}

	// compression_algorithms_client_to_server
	compression, _, err = parseNameList(payload, offset)
	return
}
