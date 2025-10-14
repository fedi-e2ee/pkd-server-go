package auxdata

import (
	"fmt"
	"strings"

	"github.com/fedi-e2ee/pkd-server-go/internal/auxvalidator"
	"golang.org/x/crypto/ssh"
)

// SSHValidator validates `ssh-v2` auxiliary data.
type SSHValidator struct{}

// NewSSHValidator creates a new SSHValidator.
func NewSSHValidator() auxvalidator.AuxDataValidator {
	return &SSHValidator{}
}

// Type returns the auxiliary data type this validator handles.
func (v *SSHValidator) Type() string {
	return "ssh-v2"
}

// Validate checks if the provided data is a valid OpenSSH public key.
func (v *SSHValidator) Validate(data string) error {
	// Trim leading/trailing whitespace, as `ssh.ParsePublicKey` is strict.
	data = strings.TrimSpace(data)

	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(data))
	if err != nil {
		return fmt.Errorf("invalid ssh public key: %w", err)
	}
	return nil
}
