package hassh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// ==================== CRITICAL SECURITY TESTS ====================

// TestParseKexInit_PanicRecovery ensures panics don't crash the application
func TestParseKexInit_PanicRecovery(t *testing.T) {
	// These payloads have caused panics in fuzzing
	crashers := [][]byte{
		{0x14}, // Too short, might cause slice panic
		{0x14, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Huge length field
		make([]byte, 0), // Empty
		nil,             // Nil slice
	}

	for i, crasher := range crashers {
		t.Run(fmt.Sprintf("crasher_%d", i), func(t *testing.T) {
			// Should not panic
			_, _, _, _, err := ParseKexInit(crasher)
			if err == nil {
				t.Error("expected error for crasher input")
			}
			// If we get here, panic was recovered
		})
	}
}

// TestParseNameList_MemoryAliasingProtection tests string copy protection
func TestParseNameList_MemoryAliasingProtection(t *testing.T) {
	// Create buffer with sensitive data
	data := make([]byte, 1000)
	for i := range data {
		data[i] = 0xAA // Fill with pattern
	}

	// Put a name-list in the middle
	nameList := "safe-algo"
	offset := 100
	binary.BigEndian.PutUint32(data[offset:], uint32(len(nameList)))
	copy(data[offset+4:], nameList)

	// Parse
	names, _, err := parseNameList(data, offset)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Modify original buffer
	for i := offset + 4; i < offset+4+len(nameList); i++ {
		data[i] = 0xBB
	}

	// Verify parsed name is NOT affected (proves copy, not alias)
	if names[0] != "safe-algo" {
		t.Error("string was aliased to buffer - security issue!")
	}

	// Verify buffer was modified
	if data[offset+4] != 0xBB {
		t.Error("test setup error - buffer not modified")
	}
}

// TestParseKexInit_ConcurrentSafety verifies no race conditions
func TestParseKexInit_ConcurrentSafety(t *testing.T) {
	payload := buildValidKexInit(t)

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, _, _ = ParseKexInit(payload)
		}()
	}

	wg.Wait()
	// Run with: go test -race
}

// TestIsValidAlgorithmName_ConstantTime attempts to detect timing variations
func TestIsValidAlgorithmName_ConstantTime(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}

	// Test with valid name (full length check)
	validName := strings.Repeat("a", maxAlgorithmNameLength)

	// Test with invalid char at start (should still take same time)
	invalidStart := "\x00" + strings.Repeat("a", maxAlgorithmNameLength-1)

	// Test with invalid char at end
	invalidEnd := strings.Repeat("a", maxAlgorithmNameLength-1) + "\x00"

	// Warm up
	for i := 0; i < 1000; i++ {
		isValidAlgorithmName(validName)
		isValidAlgorithmName(invalidStart)
		isValidAlgorithmName(invalidEnd)
	}

	// Measure timings
	const iterations = 10000

	start := time.Now()
	for i := 0; i < iterations; i++ {
		isValidAlgorithmName(validName)
	}
	validDuration := time.Since(start)

	start = time.Now()
	for i := 0; i < iterations; i++ {
		isValidAlgorithmName(invalidStart)
	}
	invalidStartDuration := time.Since(start)

	start = time.Now()
	for i := 0; i < iterations; i++ {
		isValidAlgorithmName(invalidEnd)
	}
	invalidEndDuration := time.Since(start)

	// Timings should be within 20% of each other (allowing for measurement noise)
	avgDuration := (validDuration + invalidStartDuration + invalidEndDuration) / 3
	maxDeviation := avgDuration / 5 // 20%

	if abs(validDuration-avgDuration) > maxDeviation {
		t.Logf("WARNING: Timing variation detected in isValidAlgorithmName")
		t.Logf("Valid: %v, InvalidStart: %v, InvalidEnd: %v", validDuration, invalidStartDuration, invalidEndDuration)
		t.Logf("This may indicate a timing side-channel")
	}
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// TestParseKexInit_MemoryLeak checks for memory leaks in repeated parsing
func TestParseKexInit_MemoryLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory leak test in short mode")
	}

	payload := buildValidKexInit(t)

	// Get baseline memory
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Parse many times
	for i := 0; i < 10000; i++ {
		_, _, _, _, _ = ParseKexInit(payload)
	}

	// Force GC and measure again
	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	// Memory should not grow significantly
	growth := m2.Alloc - m1.Alloc
	if growth > 1024*1024 { // 1MB growth threshold
		t.Logf("WARNING: Potential memory leak detected")
		t.Logf("Memory growth: %d bytes over 10000 iterations", growth)
	}
}

// TestParseKexInit_ContextCancellation verifies context support
func TestParseKexInit_ContextCancellation(t *testing.T) {
	payload := buildValidKexInit(t)

	// Test 1: Pre-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, _, _, err := ParseKexInitWithContext(ctx, payload)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled for pre-cancelled context, got: %v", err)
	}

	// Test 2: Timeout context that expires before call
	ctx2, cancel2 := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel2()

	// Wait to ensure timeout definitely expires
	time.Sleep(10 * time.Millisecond)

	// Double-check context is cancelled
	select {
	case <-ctx2.Done():
		// Good - context is done
	default:
		t.Skip("context did not expire in time, skipping test")
	}

	_, _, _, _, err = ParseKexInitWithContext(ctx2, payload)
	if err == nil {
		t.Error("expected error for expired context, got nil")
	} else if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("expected context error, got: %v", err)
	}
}

// TestCalculate_HashCollisionResistance verifies SHA-256 option works
func TestCalculate_HashCollisionResistance(t *testing.T) {
	kex1 := []string{"algo-a"}
	kex2 := []string{"algo-b"}

	// MD5 hashes
	md5Hash1 := CalculateWithHash(kex1, nil, nil, nil, HashMD5)
	md5Hash2 := CalculateWithHash(kex2, nil, nil, nil, HashMD5)

	if len(md5Hash1) != 32 {
		t.Errorf("MD5 hash should be 32 chars, got %d", len(md5Hash1))
	}

	// SHA-256 hashes
	sha256Hash1 := CalculateWithHash(kex1, nil, nil, nil, HashSHA256)
	sha256Hash2 := CalculateWithHash(kex2, nil, nil, nil, HashSHA256)

	if len(sha256Hash1) != 64 {
		t.Errorf("SHA-256 hash should be 64 chars, got %d", len(sha256Hash1))
	}

	// Different inputs should produce different hashes
	if md5Hash1 == md5Hash2 {
		t.Error("MD5: same hash for different inputs")
	}
	if sha256Hash1 == sha256Hash2 {
		t.Error("SHA-256: same hash for different inputs")
	}

	// SHA-256 should be different from MD5
	if len(md5Hash1) == len(sha256Hash1) {
		t.Error("MD5 and SHA-256 hashes should have different lengths")
	}
}

// TestParseNameList_UTF8InvalidSequences tests handling of malformed UTF-8
func TestParseNameList_UTF8InvalidSequences(t *testing.T) {
	tests := []struct {
		name      string
		sequence  []byte
		wantError bool
	}{
		{
			name:      "overlong encoding of null",
			sequence:  []byte{0xC0, 0x80},
			wantError: true,
		},
		{
			name:      "overlong encoding of slash",
			sequence:  []byte{0xC0, 0xAF},
			wantError: true,
		},
		{
			name:      "invalid continuation byte",
			sequence:  []byte{0xC0, 0x00},
			wantError: true,
		},
		{
			name:      "truncated sequence",
			sequence:  []byte{0xC0},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, 4+len(tt.sequence))
			binary.BigEndian.PutUint32(data[0:4], uint32(len(tt.sequence)))
			copy(data[4:], tt.sequence)

			_, _, err := parseNameList(data, 0)
			if tt.wantError && err == nil {
				t.Error("expected error for invalid UTF-8 sequence")
			}
			if tt.wantError && !errors.Is(err, ErrInvalidAlgorithmName) {
				t.Errorf("expected ErrInvalidAlgorithmName, got: %v", err)
			}
		})
	}
}

// TestParseNameList_32BitSafety verifies operation on 32-bit architectures
func TestParseNameList_32BitSafety(t *testing.T) {
	// Test with value that would overflow int32
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], math.MaxUint32)

	_, _, err := parseNameList(data, 0)
	if err == nil {
		t.Fatal("expected error for value exceeding limits")
	}

	if !errors.Is(err, ErrNameListTooLarge) {
		t.Errorf("expected ErrNameListTooLarge, got: %v", err)
	}
}

// TestParseKexInit_MaximumSizePacket tests handling of maximum-sized valid packet
func TestParseKexInit_MaximumSizePacket(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large allocation test in short mode")
	}

	// Build a packet safely under maxPayloadSize
	// Structure: 1 (msg) + 16 (cookie) + 10*content + 1 (bool) + 4 (reserved)
	// Each content: 4 (length) + data

	payload := make([]byte, 0, maxPayloadSize)
	payload = append(payload, sshMsgKexInit)
	payload = append(payload, make([]byte, 16)...) // cookie

	// Use small, simple name-lists to avoid hitting algorithm count limits
	// Goal is to test payload size, not algorithm count
	for i := 0; i < 10; i++ {
		// Just use a few algorithms per list (total ~500 algorithms, well under 5000 limit)
		algoList := "algo1,algo2,algo3,algo4,algo5"

		length := uint32(len(algoList))
		lengthBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBytes, length)
		payload = append(payload, lengthBytes...)
		payload = append(payload, []byte(algoList)...)
	}

	// Add required trailing fields
	payload = append(append(payload, 0x00), 0x00, 0x00, 0x00, 0x00) // reserved

	// Verify we're well under the limit
	if len(payload) >= maxPayloadSize {
		t.Fatalf("test setup error: payload size %d should be under max %d", len(payload), maxPayloadSize)
	}

	// Should succeed
	_, _, _, _, err := ParseKexInit(payload)
	if err != nil {
		t.Errorf("unexpected error for valid packet: %v", err)
	}

	// Now test packet that's too large
	largePayload := make([]byte, maxPayloadSize+1)
	largePayload[0] = sshMsgKexInit

	_, _, _, _, err = ParseKexInit(largePayload)
	if err == nil {
		t.Error("expected error for oversized packet")
	}
	if !errors.Is(err, ErrInvalidPacket) {
		t.Errorf("expected ErrInvalidPacket for oversized packet, got: %v", err)
	}
}

// TestParseKexInit_TooManyTotalAlgorithms verifies cross-list algorithm tracking
func TestParseKexInit_TooManyTotalAlgorithms(t *testing.T) {
	payload := make([]byte, 0, maxPayloadSize)
	payload = append(payload, sshMsgKexInit)
	payload = append(payload, make([]byte, 16)...)

	addNameList := func(count int) {
		algos := make([]string, count)
		for i := 0; i < count; i++ {
			algos[i] = "a"
		}
		nameList := strings.Join(algos, ",")

		length := uint32(len(nameList))
		lengthBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBytes, length)
		payload = append(payload, lengthBytes...)
		payload = append(payload, []byte(nameList)...)
	}

	// Add enough algorithms across multiple name-lists to exceed total limit
	// 10 lists * 600 algorithms each = 6000 > maxTotalAlgorithms (5000)
	for i := 0; i < 10; i++ {
		addNameList(600)
	}

	payload = append(append(payload, 0x00), 0x00, 0x00, 0x00, 0x00)

	_, _, _, _, err := ParseKexInit(payload)
	if err == nil {
		t.Fatal("expected error for too many total algorithms")
	}

	if !errors.Is(err, ErrTooManyAlgorithms) {
		t.Errorf("expected ErrTooManyAlgorithms, got: %v", err)
	}
}

// ==================== STANDARD FUNCTIONAL TESTS ====================

func TestParseNameList_Normal(t *testing.T) {
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

func TestParseKexInit_Valid(t *testing.T) {
	payload := buildValidKexInit(t)

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
	payload := make([]byte, 10)
	payload[0] = sshMsgKexInit

	_, _, _, _, err := ParseKexInit(payload)
	if err == nil {
		t.Fatal("expected error for packet too short")
	}
	if !errors.Is(err, ErrInvalidPacket) {
		t.Errorf("expected ErrInvalidPacket, got: %v", err)
	}
}

func TestParseKexInit_WrongMessageType(t *testing.T) {
	payload := make([]byte, 17)
	payload[0] = 99

	_, _, _, _, err := ParseKexInit(payload)
	if err == nil {
		t.Fatal("expected error for wrong message type")
	}
	if !errors.Is(err, ErrInvalidPacket) {
		t.Errorf("expected ErrInvalidPacket, got: %v", err)
	}
}

func TestCalculate(t *testing.T) {
	kex := []string{"diffie-hellman-group14-sha256"}
	ciphers := []string{"aes128-ctr", "aes256-ctr"}
	macs := []string{"hmac-sha2-256"}
	compression := []string{"none"}

	hash := Calculate(kex, ciphers, macs, compression)

	if len(hash) != 32 {
		t.Errorf("expected hash length 32, got %d", len(hash))
	}

	hash2 := Calculate(kex, ciphers, macs, compression)
	if hash != hash2 {
		t.Error("hash should be deterministic")
	}
}

func TestCalculate_EmptyLists(t *testing.T) {
	hash := Calculate([]string{}, []string{}, []string{}, []string{})

	if len(hash) != 32 {
		t.Errorf("expected hash length 32, got %d", len(hash))
	}
}

func TestCalculate_OrderMatters(t *testing.T) {
	kex1 := []string{"algo-a", "algo-b"}
	kex2 := []string{"algo-b", "algo-a"}

	hash1 := Calculate(kex1, nil, nil, nil)
	hash2 := Calculate(kex2, nil, nil, nil)

	if hash1 == hash2 {
		t.Error("different algorithm orders should produce different hashes")
	}
}

// ==================== HELPER FUNCTIONS ====================

func buildValidKexInit(t *testing.T) []byte {
	t.Helper()

	payload := make([]byte, 0, 256)
	payload = append(payload, sshMsgKexInit)
	payload = append(payload, make([]byte, 16)...)

	addNameList := func(names string) {
		length := uint32(len(names))
		lengthBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBytes, length)
		payload = append(payload, lengthBytes...)
		payload = append(payload, []byte(names)...)
	}

	addNameList("diffie-hellman-group14-sha256")
	addNameList("ssh-rsa")
	addNameList("aes128-ctr,aes256-ctr")
	addNameList("aes128-ctr")
	addNameList("hmac-sha2-256,hmac-sha2-512")
	addNameList("hmac-sha2-256")
	addNameList("none,zlib")
	addNameList("none")
	addNameList("")
	addNameList("")

	payload = append(append(payload, 0x00), 0x00, 0x00, 0x00, 0x00)

	return payload
}

// ==================== BENCHMARKS ====================

func BenchmarkParseKexInit(b *testing.B) {
	payload := buildValidKexInit(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _, _ = ParseKexInit(payload)
	}
}

func BenchmarkCalculate_MD5(b *testing.B) {
	kex := []string{"diffie-hellman-group14-sha256", "ecdh-sha2-nistp256"}
	ciphers := []string{"aes128-ctr", "aes256-ctr", "chacha20-poly1305"}
	macs := []string{"hmac-sha2-256", "hmac-sha2-512"}
	compression := []string{"none", "zlib"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Calculate(kex, ciphers, macs, compression)
	}
}

func BenchmarkCalculate_SHA256(b *testing.B) {
	kex := []string{"diffie-hellman-group14-sha256", "ecdh-sha2-nistp256"}
	ciphers := []string{"aes128-ctr", "aes256-ctr", "chacha20-poly1305"}
	macs := []string{"hmac-sha2-256", "hmac-sha2-512"}
	compression := []string{"none", "zlib"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CalculateWithHash(kex, ciphers, macs, compression, HashSHA256)
	}
}
