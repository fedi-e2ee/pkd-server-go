package auxdata

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAgeValidator(t *testing.T) {
	validator := NewAgeValidator()

	assert.Equal(t, "age-v1", validator.Type())

	t.Run("valid key", func(t *testing.T) {
		key := "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
		err := validator.Validate(key)
		assert.NoError(t, err)
	})

	t.Run("invalid key", func(t *testing.T) {
		key := "not-a-valid-age-key"
		err := validator.Validate(key)
		assert.Error(t, err)
	})

	t.Run("empty key", func(t *testing.T) {
		key := ""
		err := validator.Validate(key)
		assert.Error(t, err)
	})
}

func TestSSHValidator(t *testing.T) {
	validator := NewSSHValidator()

	assert.Equal(t, "ssh-v2", validator.Type())

	t.Run("valid key", func(t *testing.T) {
		key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGC58bY0b8LwVo3T7nCPcSKyJ3cHQE5kAUGl9+57mPTU"
		err := validator.Validate(key)
		assert.NoError(t, err)
	})

	t.Run("valid key with whitespace", func(t *testing.T) {
		key := "  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGC58bY0b8LwVo3T7nCPcSKyJ3cHQE5kAUGl9+57mPTU  "
		err := validator.Validate(key)
		assert.NoError(t, err)
	})

	t.Run("invalid key", func(t *testing.T) {
		key := "not-a-valid-ssh-key"
		err := validator.Validate(key)
		assert.Error(t, err)
	})

	t.Run("empty key", func(t *testing.T) {
		key := ""
		err := validator.Validate(key)
		assert.Error(t, err)
	})
}
