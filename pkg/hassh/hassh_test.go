package hassh

import (
	"encoding/binary"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestParseNameList_Normal(t *testing.T) {
	// Create a valid name-list: length=12, "aes,chacha20"
	data := make([]byte, 16)
	binary.BigEndian.PutUint32(data[0:4], 12)
	copy(data[4:], "aes,chacha20")

	names, offset, err := parseNameList(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if offset != 16 {
		t.Errorf("expected offset 16, got %d", offset)
	}

	expected := []string{"aes", "chacha20"}
	if !reflect.DeepEqual(names, expected) {
		t.Errorf("expected names %v, got %v", expected, names)
	}
}

func TestParseNameList_Empty(t *testing.T) {
	// Empty name-list: length=0
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data[0:4], 0)

	names, offset, err := parseNameList(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if offset != 4 {
		t.Errorf("expected offset 4, got %d", offset)
	}

	if len(names) != 0 {
		t.Errorf("expected empty slice, got %d names", len(names))
	}
}

func TestParseNameList_BufferTooShortForLength(t *testing.T) {
	// Only 3 bytes, need 4 for length field
	data := []byte{0x00, 0x00, 0x00}

	_, _, err := parseNameList(data, 0)
	if err == nil {
		t.Fatal("expected error for buffer too short")
	}
}

func TestParseNameList_BufferTooShortForData(t *testing.T) {
	// Claims 100 bytes but only has 4
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], 100)

	_, _, err := parseNameList(data, 0)
	if err == nil {
		t.Fatal("expected error for buffer too short for data")
	}
}

func TestParseNameList_MaxUint32Length(t *testing.T) {
	// Attempt to use maximum uint32 value (potential overflow)
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], math.MaxUint32)

	_, _, err := parseNameList(data, 0)
	if err == nil {
		t.Fatal("expected error for excessive length")
	}

	// Should specifically reject lengths > maxNameListLength
	if !strings.Contains(err.Error(), "name-list too large") {
		t.Errorf("expected 'name-list too large' error, got: %v", err)
	}
}

func TestParseNameList_ExceedsMaxLength(t *testing.T) {
	// Length just over the max (1MB + 1)
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], maxNameListLength+1)

	_, _, err := parseNameList(data, 0)
	if err == nil {
		t.Fatal("expected error for length exceeding maximum")
	}
}

func TestParseNameList_AtMaxLength(t *testing.T) {
	// Length exactly at max should work if buffer is available
	// (though we won't actually allocate 1MB for this test)
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], maxNameListLength)

	_, _, err := parseNameList(data, 0)
	// Should fail on buffer too short, not on length validation
	if err == nil {
		t.Fatal("expected error for buffer too short")
	}
	if err.Error() != "buffer too short for name-list data: need 1048576 bytes, have 4" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParseNameList_OffsetOverflow(t *testing.T) {
	// Test case where offset + length would overflow
	// Create buffer with length field at offset 80
	data := make([]byte, 100)
	// Put length=50 at offset 80 (where we'll start reading)
	binary.BigEndian.PutUint32(data[80:84], 50)

	// Start at offset 80: we can read the 4-byte length field (80+4=84 <= 100)
	// But then we'd need 50 more bytes (84+50=134 > 100)
	_, _, err := parseNameList(data, 80)
	if err == nil {
		t.Fatal("expected error when offset+length exceeds buffer")
	}
	if !strings.Contains(err.Error(), "buffer too short for name-list data") {
		t.Errorf("expected 'buffer too short for name-list data' error, got: %v", err)
	}
}

func TestParseKexInit_Valid(t *testing.T) {
	// Build a complete RFC 4253 compliant KEXINIT packet
	payload := make([]byte, 0, 256)

	// Message type
	payload = append(payload, sshMsgKexInit)

	// Cookie (16 random bytes)
	payload = append(payload, make([]byte, 16)...)

	// Helper to add name-list
	addNameList := func(names string) {
		length := uint32(len(names))
		lengthBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBytes, length)
		payload = append(payload, lengthBytes...)
		payload = append(payload, []byte(names)...)
	}

	// kex_algorithms
	addNameList("diffie-hellman-group14-sha256")

	// server_host_key_algorithms
	addNameList("ssh-rsa")

	// encryption_algorithms_client_to_server
	addNameList("aes128-ctr,aes256-ctr")

	// encryption_algorithms_server_to_client
	addNameList("aes128-ctr")

	// mac_algorithms_client_to_server
	addNameList("hmac-sha2-256,hmac-sha2-512")

	// mac_algorithms_server_to_client
	addNameList("hmac-sha2-256")

	// compression_algorithms_client_to_server
	addNameList("none,zlib")

	// compression_algorithms_server_to_client (RFC compliance)
	addNameList("none")

	// languages_client_to_server (RFC compliance - typically empty)
	addNameList("")

	// languages_server_to_client (RFC compliance - typically empty)
	addNameList("")

	// first_kex_packet_follows (boolean - 1 byte)
	payload = append(payload, 0x00) // false

	// reserved (uint32 - must be 0)
	payload = append(payload, 0x00, 0x00, 0x00, 0x00)

	kex, ciphers, macs, compression, err := ParseKexInit(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedKex := []string{"diffie-hellman-group14-sha256"}
	if !reflect.DeepEqual(kex, expectedKex) {
		t.Errorf("expected kex %v, got %v", expectedKex, kex)
	}

	expectedCiphers := []string{"aes128-ctr", "aes256-ctr"}
	if !reflect.DeepEqual(ciphers, expectedCiphers) {
		t.Errorf("expected ciphers %v, got %v", expectedCiphers, ciphers)
	}

	expectedMacs := []string{"hmac-sha2-256", "hmac-sha2-512"}
	if !reflect.DeepEqual(macs, expectedMacs) {
		t.Errorf("expected macs %v, got %v", expectedMacs, macs)
	}

	expectedCompression := []string{"none", "zlib"}
	if !reflect.DeepEqual(compression, expectedCompression) {
		t.Errorf("expected compression %v, got %v", expectedCompression, compression)
	}
}

func TestParseKexInit_TooShort(t *testing.T) {
	// Only 10 bytes (need at least 17)
	payload := make([]byte, 10)
	payload[0] = sshMsgKexInit

	_, _, _, _, err := ParseKexInit(payload)
	if err == nil {
		t.Fatal("expected error for packet too short")
	}
}

func TestParseKexInit_WrongMessageType(t *testing.T) {
	// Valid length but wrong message type
	payload := make([]byte, 17)
	payload[0] = 99 // Not SSH_MSG_KEXINIT

	_, _, _, _, err := ParseKexInit(payload)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
}

func TestParseKexInit_MalformedNameList(t *testing.T) {
	// Valid header but malformed name-list
	payload := make([]byte, 17)
	payload[0] = sshMsgKexInit

	// Add a name-list with excessive length
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, math.MaxUint32)
	payload = append(payload, lengthBytes...)

	_, _, _, _, err := ParseKexInit(payload)
	if err == nil {
		t.Fatal("expected error for malformed name-list")
	}
}

func TestParseKexInit_IncompletePacket_MissingLanguages(t *testing.T) {
	// Packet stops after compression_algorithms_client_to_server
	// Missing: compression_server_to_client, both languages, boolean, reserved
	payload := make([]byte, 0, 128)
	payload = append(payload, sshMsgKexInit)
	payload = append(payload, make([]byte, 16)...)

	addNameList := func(names string) {
		length := uint32(len(names))
		lengthBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBytes, length)
		payload = append(payload, lengthBytes...)
		payload = append(payload, []byte(names)...)
	}

	// Add all name-lists up to compression_client_to_server
	for i := 0; i < 7; i++ {
		addNameList("test")
	}
	// Stop here - packet is incomplete per RFC

	_, _, _, _, err := ParseKexInit(payload)
	if err == nil {
		t.Fatal("expected error for incomplete packet (missing languages/boolean/reserved)")
	}
}

func TestParseKexInit_MissingBoolean(t *testing.T) {
	// Complete all name-lists but missing first_kex_packet_follows boolean
	payload := make([]byte, 0, 128)
	payload = append(payload, sshMsgKexInit)
	payload = append(payload, make([]byte, 16)...)

	addNameList := func(names string) {
		length := uint32(len(names))
		lengthBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBytes, length)
		payload = append(payload, lengthBytes...)
		payload = append(payload, []byte(names)...)
	}

	// Add all 10 name-lists
	for i := 0; i < 10; i++ {
		addNameList("")
	}
	// Stop here - missing boolean and reserved

	_, _, _, _, err := ParseKexInit(payload)
	if err == nil {
		t.Fatal("expected error for missing first_kex_packet_follows boolean")
	}
	if err.Error() != "buffer too short for first_kex_packet_follows" {
		t.Errorf("wrong error message: %v", err)
	}
}

func TestParseKexInit_MissingReserved(t *testing.T) {
	// Complete all name-lists and boolean but missing reserved uint32
	payload := make([]byte, 0, 128)
	payload = append(payload, sshMsgKexInit)
	payload = append(payload, make([]byte, 16)...)

	addNameList := func(names string) {
		length := uint32(len(names))
		lengthBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBytes, length)
		payload = append(payload, lengthBytes...)
		payload = append(payload, []byte(names)...)
	}

	// Add all 10 name-lists
	for i := 0; i < 10; i++ {
		addNameList("")
	}
	// Add boolean
	payload = append(payload, 0x00)
	// Stop here - missing reserved uint32

	_, _, _, _, err := ParseKexInit(payload)
	if err == nil {
		t.Fatal("expected error for missing reserved field")
	}
	if err.Error() != "buffer too short for reserved field" {
		t.Errorf("wrong error message: %v", err)
	}
}

func TestCalculate(t *testing.T) {
	kex := []string{"diffie-hellman-group14-sha256"}
	ciphers := []string{"aes128-ctr", "aes256-ctr"}
	macs := []string{"hmac-sha2-256"}
	compression := []string{"none"}

	hash := Calculate(kex, ciphers, macs, compression)

	// Should be a valid hex string of length 32 (MD5 = 128 bits = 16 bytes = 32 hex chars)
	if len(hash) != 32 {
		t.Errorf("expected hash length 32, got %d", len(hash))
	}

	// Should be deterministic
	hash2 := Calculate(kex, ciphers, macs, compression)
	if hash != hash2 {
		t.Error("hash should be deterministic")
	}

	// Different input should produce different hash
	kex2 := []string{"different-algorithm"}
	hash3 := Calculate(kex2, ciphers, macs, compression)
	if hash == hash3 {
		t.Error("different inputs should produce different hashes")
	}
}

func TestCalculate_EmptyLists(t *testing.T) {
	// Edge case: all empty lists
	hash := Calculate([]string{}, []string{}, []string{}, []string{})

	if len(hash) != 32 {
		t.Errorf("expected hash length 32, got %d", len(hash))
	}

	// Should produce hash of ";;;" string
	expected := Calculate([]string{}, []string{}, []string{}, []string{})
	if hash != expected {
		t.Error("empty lists should produce consistent hash")
	}
}

// Additional edge case tests

func TestParseNameList_TrailingComma(t *testing.T) {
	// Name-list with trailing comma
	data := make([]byte, 20)
	nameList := "algo1,algo2,"
	binary.BigEndian.PutUint32(data[0:4], uint32(len(nameList)))
	copy(data[4:], nameList)

	names, _, err := parseNameList(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Current behavior: strings.Split creates an empty string at the end
	if len(names) != 3 {
		t.Errorf("expected 3 elements (including empty string), got %d", len(names))
	}
	if names[2] != "" {
		t.Errorf("expected empty string at end, got %q", names[2])
	}
}

func TestParseNameList_ConsecutiveCommas(t *testing.T) {
	// Name-list with consecutive commas
	data := make([]byte, 20)
	nameList := "algo1,,algo3"
	binary.BigEndian.PutUint32(data[0:4], uint32(len(nameList)))
	copy(data[4:], nameList)

	names, _, err := parseNameList(data, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Current behavior: strings.Split creates empty strings
	expected := []string{"algo1", "", "algo3"}
	if !reflect.DeepEqual(names, expected) {
		t.Errorf("expected %v, got %v", expected, names)
	}
}

func TestCalculate_OrderMatters(t *testing.T) {
	// Verify that algorithm order affects the hash
	kex1 := []string{"algo-a", "algo-b"}
	kex2 := []string{"algo-b", "algo-a"}

	hash1 := Calculate(kex1, nil, nil, nil)
	hash2 := Calculate(kex2, nil, nil, nil)

	if hash1 == hash2 {
		t.Error("different algorithm orders should produce different hashes")
	}
}

// Benchmark to ensure performance isn't degraded by safety checks
func BenchmarkParseNameList(b *testing.B) {
	data := make([]byte, 100)
	binary.BigEndian.PutUint32(data[0:4], 50)
	copy(data[4:], "algorithm1,algorithm2,algorithm3,algorithm4,al")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = parseNameList(data, 0)
	}
}

func BenchmarkCalculate(b *testing.B) {
	kex := []string{"diffie-hellman-group14-sha256", "ecdh-sha2-nistp256"}
	ciphers := []string{"aes128-ctr", "aes256-ctr", "chacha20-poly1305"}
	macs := []string{"hmac-sha2-256", "hmac-sha2-512"}
	compression := []string{"none", "zlib"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Calculate(kex, ciphers, macs, compression)
	}
}
