// Package netguard provides always-on protection against outbound SSH
// connections to dangerous destinations: loopback (all address families,
// including ::1 and IPv4-mapped forms) and link-local ranges (including the
// cloud metadata endpoint 169.254.169.254).
//
// Checks are wired into the dial path via Control callbacks so they run on
// the RESOLVED address right before the TCP connection is made. This closes
// the DNS TOCTOU window where a hostile hostname resolves to a public IP
// during pre-flight checks but to loopback when actually dialed.
package netguard

import (
	"fmt"
	"net"
	"syscall"
)

var (
	builtinBlockedV4 = mustParseCIDRs(
		"127.0.0.0/8",    // IPv4 loopback
		"169.254.0.0/16", // IPv4 link-local (incl. cloud metadata)
	)
	builtinBlockedV6 = mustParseCIDRs(
		"::1/128",   // IPv6 loopback
		"fe80::/10", // IPv6 link-local
	)
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("netguard: invalid builtin CIDR %s: %v", cidr, err))
		}
		nets = append(nets, ipNet)
	}
	return nets
}

// contains checks ip against nets of its own address family. net.ParseIP
// returns IPv4 addresses in 16-byte IPv4-mapped form, so a naive Contains
// against an IPv6 range like ::ffff:0:0/96 would wrongly match every IPv4
// address; normalizing via To4 keeps families separate.
func contains(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsBlockedIP reports whether ip matches the always-on blocked ranges.
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if to4 := ip.To4(); to4 != nil {
		return contains(builtinBlockedV4, to4)
	}
	return contains(builtinBlockedV6, ip)
}

// MatchesAny reports whether ip is contained in any of the given networks,
// matching within its own address family (see contains).
func MatchesAny(ip net.IP, nets []*net.IPNet) bool {
	if to4 := ip.To4(); to4 != nil {
		return contains(nets, to4)
	}
	return contains(nets, ip)
}

// ControlFunc returns a net.Dialer Control callback that rejects connections
// whose final resolved address falls into the builtin blocked ranges or any
// of the extra networks (the user-configured blacklist). This is evaluated
// per real connection attempt, eliminating DNS rebinding TOCTOU bypasses.
func ControlFunc(extra []*net.IPNet) func(string, string, syscall.RawConn) error {
	return func(_ string, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("invalid dial address %q: %w", address, err)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			// Literal hostnames never reach Control; only resolved IPs do.
			return fmt.Errorf("unresolved address %q", host)
		}
		if IsBlockedIP(ip) || MatchesAny(ip, extra) {
			return fmt.Errorf("connection to %s blocked: blacklisted address", ip)
		}
		return nil
	}
}

// ParseCIDRs parses a list of CIDR strings, skipping empty entries.
func ParseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		nets = append(nets, ipNet)
	}
	return nets, nil
}
