package hassh

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ==================== SSH CONNECTION BENCHMARKS ====================
// These benchmarks simulate real SSH connection scenarios and measure
// the overhead of HASSH fingerprinting during the handshake process.

// BenchmarkKEXINITParsing_RealWorld benchmarks parsing real SSH KEXINIT packets
func BenchmarkKEXINITParsing_RealWorld(b *testing.B) {
	// Simulate real-world KEXINIT packets from different SSH clients
	testCases := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "OpenSSH_8.2",
			payload: buildRealWorldKexInit(b, openssh82Algorithms()),
		},
		{
			name:    "PuTTY_0.76",
			payload: buildRealWorldKexInit(b, putty076Algorithms()),
		},
		{
			name:    "libssh_0.9",
			payload: buildRealWorldKexInit(b, libssh09Algorithms()),
		},
		{
			name:    "Dropbear_2020.81",
			payload: buildRealWorldKexInit(b, dropbear2020Algorithms()),
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				kex, ciphers, macs, compression, err := ParseKexInit(tc.payload)
				if err != nil {
					b.Fatalf("parse error: %v", err)
				}
				_ = Calculate(kex, ciphers, macs, compression)
			}
			b.StopTimer()

			// Calculate throughput
			bytesPerOp := int64(len(tc.payload))
			b.SetBytes(bytesPerOp)
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "parses/sec")
		})
	}
}

// BenchmarkConnectionRate measures maximum connection rate with fingerprinting
func BenchmarkConnectionRate(b *testing.B) {
	server, _ := setupTestSSHServer(b)
	defer server.Close()

	clientConfig := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	// Test different concurrency levels
	concurrencyLevels := []int{1, 10, 50, 100}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("concurrent_%d", concurrency), func(b *testing.B) {
			sem := make(chan struct{}, concurrency)

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					sem <- struct{}{}
					go func() {
						defer func() { <-sem }()

						conn, err := ssh.Dial("tcp", server.Addr().String(), clientConfig)
						if err != nil {
							return
						}
						conn.Close()
					}()
				}
			})
			b.StopTimer()

			// Wait for all goroutines to finish
			for i := 0; i < cap(sem); i++ {
				sem <- struct{}{}
			}

			connectionsPerSec := float64(b.N) / b.Elapsed().Seconds()
			b.ReportMetric(connectionsPerSec, "conn/sec")
		})
	}
}

// BenchmarkFingerprintCacheLookup benchmarks fingerprint cache performance
func BenchmarkFingerprintCacheLookup(b *testing.B) {
	// Simulate a fingerprint cache
	cache := make(map[string]*ClientInfo)
	mu := sync.RWMutex{}

	// Pre-populate cache with 10,000 fingerprints
	for i := 0; i < 10000; i++ {
		fingerprint := fmt.Sprintf("fingerprint_%d", i)
		cache[fingerprint] = &ClientInfo{
			Fingerprint: fingerprint,
			ClientName:  fmt.Sprintf("client_%d", i),
			FirstSeen:   time.Now(),
		}
	}

	// Test fingerprint to lookup
	testFingerprint := "fingerprint_5000"

	b.Run("cache_hit", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mu.RLock()
			_, ok := cache[testFingerprint]
			mu.RUnlock()
			if !ok {
				b.Fatal("cache miss on hit test")
			}
		}
	})

	b.Run("cache_miss", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mu.RLock()
			_, ok := cache["nonexistent"]
			mu.RUnlock()
			if ok {
				b.Fatal("cache hit on miss test")
			}
		}
	})
}

// BenchmarkHashAlgorithms compares MD5 vs SHA256 performance
func BenchmarkHashAlgorithms(b *testing.B) {
	kex := []string{"curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"}
	ciphers := []string{"aes128-gcm", "aes256-gcm", "chacha20-poly1305", "aes128-ctr", "aes256-ctr"}
	macs := []string{"hmac-sha2-256", "hmac-sha2-512"}
	compression := []string{"none", "zlib"}

	b.Run("MD5", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = CalculateWithHash(kex, ciphers, macs, compression, HashMD5)
		}
		b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "hashes/sec")
	})

	b.Run("SHA256", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = CalculateWithHash(kex, ciphers, macs, compression, HashSHA256)
		}
		b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "hashes/sec")
	})
}

// BenchmarkParsingComplexity tests parsing with different payload complexities
func BenchmarkParsingComplexity(b *testing.B) {
	testCases := []struct {
		name          string
		algosPerList  int
		algorithmName string
	}{
		{"simple_5", 5, "algo"},
		{"medium_20", 20, "algorithm"},
		{"complex_50", 50, "algo"}, // Reduced to stay under 16KB
		{"large_80", 80, "alg"},    // Reduced from 100
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			// Build payload with specified complexity
			payload := buildComplexKexInit(b, tc.algosPerList, tc.algorithmName)

			// Skip if payload is too large (should not happen with new limits)
			if len(payload) > maxPayloadSize {
				b.Skipf("payload size %d exceeds max %d - test configuration error", len(payload), maxPayloadSize)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, _, _, err := ParseKexInit(payload)
				if err != nil {
					b.Fatalf("parse error: %v (payload size: %d)", err, len(payload))
				}
			}

			b.SetBytes(int64(len(payload)))
			b.ReportMetric(float64(len(payload)*b.N)/b.Elapsed().Seconds()/1024/1024, "MB/sec")
		})
	}
}

// BenchmarkMemoryAllocation measures memory allocation patterns
func BenchmarkMemoryAllocation(b *testing.B) {
	payload := buildRealWorldKexInit(b, openssh82Algorithms())

	b.Run("with_allocation", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			kex, ciphers, macs, compression, _ := ParseKexInit(payload)
			_ = Calculate(kex, ciphers, macs, compression)
		}
	})

	b.Run("parse_only", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, _, _, _ = ParseKexInit(payload)
		}
	})

	b.Run("calculate_only", func(b *testing.B) {
		kex, ciphers, macs, compression, _ := ParseKexInit(payload)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = Calculate(kex, ciphers, macs, compression)
		}
	})
}

// ==================== HELPER FUNCTIONS ====================

type ClientInfo struct {
	Fingerprint string
	ClientName  string
	FirstSeen   time.Time
}

type Algorithms struct {
	Kex        []string
	HostKey    []string
	CiphersC2S []string
	CiphersS2C []string
	MACsC2S    []string
	MACsS2C    []string
	CompC2S    []string
	CompS2C    []string
}

func setupTestSSHServer(b *testing.B) (net.Listener, *ssh.ServerConfig) {
	b.Helper()

	// Generate host key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("failed to generate key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		b.Fatalf("failed to create signer: %v", err)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) == "testpass" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected")
		},
	}
	config.AddHostKey(signer)

	// Start listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to listen: %v", err)
	}

	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _, _, _ = ssh.NewServerConn(c, config)
			}(conn)
		}
	}()

	return listener, config
}

func openssh82Algorithms() Algorithms {
	return Algorithms{
		Kex:        []string{"curve25519-sha256", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256"},
		HostKey:    []string{"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ecdsa-sha2-nistp256", "ssh-ed25519"},
		CiphersC2S: []string{"chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"},
		CiphersS2C: []string{"chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"},
		MACsC2S:    []string{"umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com"},
		MACsS2C:    []string{"umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com"},
		CompC2S:    []string{"none", "zlib@openssh.com"},
		CompS2C:    []string{"none", "zlib@openssh.com"},
	}
}

func putty076Algorithms() Algorithms {
	return Algorithms{
		Kex:        []string{"ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group16-sha512", "diffie-hellman-group15-sha512", "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"},
		HostKey:    []string{"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ssh-dss"},
		CiphersC2S: []string{"aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"},
		CiphersS2C: []string{"aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"},
		MACsC2S:    []string{"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"},
		MACsS2C:    []string{"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"},
		CompC2S:    []string{"none"},
		CompS2C:    []string{"none"},
	}
}

func libssh09Algorithms() Algorithms {
	return Algorithms{
		Kex:        []string{"curve25519-sha256", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group18-sha512", "diffie-hellman-group16-sha512"},
		HostKey:    []string{"ssh-ed25519", "ecdsa-sha2-nistp521", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"},
		CiphersC2S: []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"},
		CiphersS2C: []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"},
		MACsC2S:    []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com"},
		MACsS2C:    []string{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com"},
		CompC2S:    []string{"none"},
		CompS2C:    []string{"none"},
	}
}

func dropbear2020Algorithms() Algorithms {
	return Algorithms{
		Kex:        []string{"curve25519-sha256", "ecdh-sha2-nistp521", "ecdh-sha2-nistp384", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"},
		HostKey:    []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "ssh-rsa"},
		CiphersC2S: []string{"chacha20-poly1305@openssh.com", "aes128-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"},
		CiphersS2C: []string{"chacha20-poly1305@openssh.com", "aes128-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"},
		MACsC2S:    []string{"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"},
		MACsS2C:    []string{"hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"},
		CompC2S:    []string{"none"},
		CompS2C:    []string{"none"},
	}
}

func buildRealWorldKexInit(b *testing.B, algos Algorithms) []byte {
	b.Helper()

	payload := make([]byte, 0, 2048)
	payload = append(payload, sshMsgKexInit)
	payload = append(payload, make([]byte, 16)...) // cookie

	addNameList := func(names []string) {
		nameList := ""
		for i, name := range names {
			if i > 0 {
				nameList += ","
			}
			nameList += name
		}
		length := uint32(len(nameList))
		lengthBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBytes, length)
		payload = append(payload, lengthBytes...)
		payload = append(payload, []byte(nameList)...)
	}

	addNameList(algos.Kex)
	addNameList(algos.HostKey)
	addNameList(algos.CiphersC2S)
	addNameList(algos.CiphersS2C)
	addNameList(algos.MACsC2S)
	addNameList(algos.MACsS2C)
	addNameList(algos.CompC2S)
	addNameList(algos.CompS2C)
	addNameList([]string{}) // languages C2S
	addNameList([]string{}) // languages S2C

	payload = append(payload, 0x00)                   // boolean
	payload = append(payload, 0x00, 0x00, 0x00, 0x00) // reserved

	return payload
}

func buildComplexKexInit(b *testing.B, algosPerList int, algorithmName string) []byte {
	b.Helper()

	payload := make([]byte, 0, maxPayloadSize)
	payload = append(payload, sshMsgKexInit)
	payload = append(payload, make([]byte, 16)...)

	addNameList := func(count int) {
		algos := make([]string, count)
		for i := 0; i < count; i++ {
			algos[i] = fmt.Sprintf("%s%d", algorithmName, i)
		}
		nameList := ""
		for i, algo := range algos {
			if i > 0 {
				nameList += ","
			}
			nameList += algo
		}
		length := uint32(len(nameList))
		lengthBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBytes, length)
		payload = append(payload, lengthBytes...)
		payload = append(payload, []byte(nameList)...)

		// Safety check: ensure we don't exceed max payload size
		if len(payload) > maxPayloadSize-100 {
			b.Fatalf("payload approaching size limit at %d bytes", len(payload))
		}
	}

	for i := 0; i < 10; i++ {
		addNameList(algosPerList)
	}

	payload = append(payload, 0x00)
	payload = append(payload, 0x00, 0x00, 0x00, 0x00)

	return payload
}
