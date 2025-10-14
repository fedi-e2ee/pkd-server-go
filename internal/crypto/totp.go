package crypto

import (
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// ValidateTOTP checks if the provided passcode is a valid TOTP for the given secret.
func ValidateTOTP(secret, passcode string) bool {
	valid, err := totp.ValidateCustom(passcode, secret, time.Now().UTC(), totp.ValidateOpts{
		// Per the specification, we allow a 30-second clock drift.
		Skew: 1,
		// The other parameters should match what the client uses to generate the OTP.
		// Using common defaults here.
		Period:    30,
		Algorithm: otp.AlgorithmSHA1,
		Digits:    otp.DigitsSix,
	})
	if err != nil {
		// Log the error for debugging, but treat it as a validation failure.
		// For example, if the secret is malformed.
		return false
	}
	return valid
}
