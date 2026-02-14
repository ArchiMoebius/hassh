// pkg/proxy/proxyprotocol.go
package proxy

import (
	"encoding/binary"
	"net"
)

// PROXY protocol v2 header for TCP over IPv4/IPv6
// Spec: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

const (
	proxyProtocolV2Signature = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
	proxyProtocolVersion     = 0x20 // Version 2, PROXY command
	afInet                   = 0x11 // AF_INET (IPv4) + STREAM
	afInet6                  = 0x21 // AF_INET6 (IPv6) + STREAM
)

// buildProxyProtocolV2Header creates a PROXY protocol v2 header
func buildProxyProtocolV2Header(clientAddr, proxyAddr net.Addr) ([]byte, error) {
	clientTCP, ok := clientAddr.(*net.TCPAddr)
	if !ok {
		return nil, nil // Skip if not TCP
	}

	proxyTCP, ok := proxyAddr.(*net.TCPAddr)
	if !ok {
		return nil, nil
	}

	// Determine address family
	clientIP := clientTCP.IP
	proxyIP := proxyTCP.IP

	var header []byte
	var addressFamily byte

	// Check if both are IPv4
	if clientIP4 := clientIP.To4(); clientIP4 != nil {
		if proxyIP4 := proxyIP.To4(); proxyIP4 != nil {
			addressFamily = afInet
			header = make([]byte, 28) // 12 byte header + 12 byte IPv4 addresses + 4 byte ports

			// Source address (client)
			copy(header[12:16], clientIP4)
			// Destination address (proxy)
			copy(header[16:20], proxyIP4)
			// Source port
			binary.BigEndian.PutUint16(header[20:22], uint16(clientTCP.Port))
			// Destination port
			binary.BigEndian.PutUint16(header[22:24], uint16(proxyTCP.Port))
		}
	} else {
		// IPv6
		addressFamily = afInet6
		header = make([]byte, 52) // 12 byte header + 32 byte IPv6 addresses + 4 byte ports

		// Source address (client)
		copy(header[12:28], clientIP.To16())
		// Destination address (proxy)
		copy(header[28:44], proxyIP.To16())
		// Source port
		binary.BigEndian.PutUint16(header[44:46], uint16(clientTCP.Port))
		// Destination port
		binary.BigEndian.PutUint16(header[46:48], uint16(proxyTCP.Port))
	}

	if header == nil {
		return nil, nil
	}

	// Signature (12 bytes)
	copy(header[0:12], proxyProtocolV2Signature)

	// Version and command
	header[12] = proxyProtocolVersion

	// Address family and protocol
	header[13] = addressFamily

	// Length of addresses (following the header)
	addrLen := len(header) - 16
	binary.BigEndian.PutUint16(header[14:16], uint16(addrLen))

	return header, nil
}
