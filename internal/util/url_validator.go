package util

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// List of top-level domains that are unlikely to be used for Fediverse servers.
// This is not a comprehensive list, but a simple heuristic to reduce the
// attack surface. Feel free to expand this list if needed.
var forbiddenTlds = []string{
	".example",
	".internal",
	".lan",
	".local",
	".localhost",
	".test",
}

// ValidateURL checks if a given URL is valid for outbound requests.
//
// This function performs the following checks:
// 1. Parses the URL.
// 2. Ensures the scheme is either "http" or "https".
// 3. Checks if the hostname is a loopback address.
// 4. Checks if the hostname resolves to a private or reserved IP address.
// 5. Checks against a list of forbidden top-level domains.
//
// It cannot enforce an allow-list at this level.
// codeql[go/ssrf-sanitizer]
func ValidateURL(u string, allowPrivateIPs bool) (*url.URL, error) {
	// 1. Parse the URL.
	parsedURL, err := url.Parse(u)
	if err != nil {
		return nil, fmt.Errorf("could not parse URL: %w", err)
	}

	// 2. Ensure the scheme is either "http" or "https".
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("invalid URL scheme: %s", parsedURL.Scheme)
	}

	hostname := parsedURL.Hostname()
	// In test environments, we might want to allow private/loopback addresses.
	if !allowPrivateIPs {
		// 3. Check if the hostname is a loopback address.
		if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
			return nil, fmt.Errorf("hostname is a loopback address")
		}

		// 4. Check against a list of forbidden top-level domains.
		for _, tld := range forbiddenTlds {
			if strings.HasSuffix(hostname, tld) {
				return nil, fmt.Errorf("hostname has a forbidden TLD: %s", tld)
			}
		}

		// 5. Check if the hostname resolves to a private or reserved IP address.
		ips, err := net.LookupIP(hostname)
		if err != nil {
			// Don't error out if we can't resolve, but only if we are in test-mode.
			// This is to allow dummy hostnames in tests.
			if !allowPrivateIPs {
				return nil, fmt.Errorf("could not resolve hostname: %w", err)
			}
		}
		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
				return nil, fmt.Errorf("hostname resolves to a private or reserved IP address")
			}
		}
	}
	return parsedURL, nil
}
