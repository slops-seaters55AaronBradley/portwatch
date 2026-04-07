// Package scanner provides functionality to scan and retrieve open network ports
// on the local system by reading from /proc/net or using system calls.
package scanner

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Protocol represents a network protocol type.
type Protocol string

const (
	TCP  Protocol = "tcp"
	TCP6 Protocol = "tcp6"
	UDP  Protocol = "udp"
	UDP6 Protocol = "udp6"
)

// PortEntry represents a single open port with its associated metadata.
type PortEntry struct {
	Protocol  Protocol
	LocalAddr string
	LocalPort uint16
	PID       int
	ProcessName string
}

// String returns a human-readable representation of a PortEntry.
func (p PortEntry) String() string {
	return fmt.Sprintf("%s %s:%d (pid=%d name=%s)", p.Protocol, p.LocalAddr, p.LocalPort, p.PID, p.ProcessName)
}

// Scanner scans the local system for open ports.
type Scanner struct {
	Protocols []Protocol
}

// New creates a new Scanner that checks TCP and UDP ports by default.
func New() *Scanner {
	return &Scanner{
		Protocols: []Protocol{TCP, TCP6, UDP, UDP6},
	}
}

// Scan returns all currently open port entries on the system.
func (s *Scanner) Scan() ([]PortEntry, error) {
	var entries []PortEntry

	for _, proto := range s.Protocols {
		path := fmt.Sprintf("/proc/net/%s", string(proto))
		results, err := parseProcNet(path, proto)
		if err != nil {
			// Non-fatal: some protocols may not be available
			continue
		}
		entries = append(entries, results...)
	}

	return entries, nil
}

// parseProcNet reads and parses a /proc/net/{tcp,udp,tcp6,udp6} file.
func parseProcNet(path string, proto Protocol) ([]PortEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var entries []PortEntry
	scanner := bufio.NewScanner(f)

	// Skip the header line
	scanner.Scan()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Only include LISTEN (0A) for TCP, or unconditionally for UDP
		state := fields[3]
		if (proto == TCP || proto == TCP6) && state != "0A" {
			continue
		}

		addr, port, err := parseHexAddr(fields[1])
		if err != nil {
			continue
		}

		entries = append(entries, PortEntry{
			Protocol:    proto,
			LocalAddr:   addr,
			LocalPort:   port,
			PID:         -1,
			ProcessName: "",
		})
	}

	return entries, scanner.Err()
}

// parseHexAddr parses a hex-encoded address:port string from /proc/net files.
// Format: "0100007F:0050" (little-endian hex IP : hex port)
func parseHexAddr(hexAddr string) (string, uint16, error) {
	parts := strings.SplitN(hexAddr, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid addr format: %s", hexAddr)
	}

	ipHex := parts[0]
	portHex := parts[1]

	portVal, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("parse port: %w", err)
	}

	// IPv4: 4 bytes little-endian
	var ip net.IP
	if len(ipHex) == 8 {
		ipBytes := make([]byte, 4)
		for i := 0; i < 4; i++ {
			b, err := strconv.ParseUint(ipHex[i*2:i*2+2], 16, 8)
			if err != nil {
				return "", 0, err
			}
			ipBytes[3-i] = byte(b)
		}
		ip = net.IP(ipBytes)
	} else {
		// IPv6: 16 bytes little-endian in 4-byte groups
		ipBytes := make([]byte, 16)
		for group := 0; group < 4; group++ {
			for i := 0; i < 4; i++ {
				offset := group*8 + i*2
				b, err := strconv.ParseUint(ipHex[offset:offset+2], 16, 8)
				if err != nil {
					return "", 0, err
				}
				ipBytes[group*4+(3-i)] = byte(b)
			}
		}
		ip = net.IP(ipBytes)
	}

	return ip.String(), uint16(portVal), nil
}
