package auxdata

import (
	"fmt"

	"filippo.io/age"
	"github.com/fedi-e2ee/pkd-server-go/internal/auxvalidator"
)

// AgeValidator validates `age-v1` auxiliary data.
type AgeValidator struct{}

// NewAgeValidator creates a new AgeValidator.
func NewAgeValidator() auxvalidator.AuxDataValidator {
	return &AgeValidator{}
}

// Type returns the auxiliary data type this validator handles.
func (v *AgeValidator) Type() string {
	return "age-v1"
}

// Validate checks if the provided data is a valid age public key.
func (v *AgeValidator) Validate(data string) error {
	_, err := age.ParseX25519Recipient(data)
	if err != nil {
		return fmt.Errorf("invalid age public key: %w", err)
	}
	return nil
}
