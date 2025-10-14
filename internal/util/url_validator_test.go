package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateURL(t *testing.T) {
	testCases := []struct {
		name        string
		url         string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid HTTPS URL",
			url:         "https://example.com",
			expectError: false,
		},
		{
			name:        "Valid HTTP URL",
			url:         "http://example.com",
			expectError: false,
		},
		{
			name:        "Invalid Scheme",
			url:         "ftp://example.com",
			expectError: true,
			errorMsg:    "invalid URL scheme: ftp",
		},
		{
			name:        "Loopback Address (localhost)",
			url:         "http://localhost/foo",
			expectError: true,
			errorMsg:    "hostname is a loopback address",
		},
		{
			name:        "Loopback Address (127.0.0.1)",
			url:         "http://127.0.0.1/bar",
			expectError: true,
			errorMsg:    "hostname is a loopback address",
		},
		{
			name:        "Loopback Address (::1)",
			url:         "http://[::1]/baz",
			expectError: true,
			errorMsg:    "hostname is a loopback address",
		},
		{
			name:        "Forbidden TLD (.local)",
			url:         "http://server.local/qux",
			expectError: true,
			errorMsg:    "hostname has a forbidden TLD: .local",
		},
		{
			name:        "Forbidden TLD (.internal)",
			url:         "https://db.internal/api",
			expectError: true,
			errorMsg:    "hostname has a forbidden TLD: .internal",
		},
		{
			name:        "Malformed URL",
			url:         "://foo",
			expectError: true,
			errorMsg:    "could not parse URL",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateURL(tc.url, false)
			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
