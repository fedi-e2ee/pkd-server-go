package tests

import (
	"context"
	"testing"

	"github.com/fedi-e2ee/pkd-server-go/internal/auxvalidator"
	"github.com/fedi-e2ee/pkd-server-go/internal/domain"
	"github.com/fedi-e2ee/pkd-server-go/internal/auxdata"
	"github.com/fedi-e2ee/pkd-server-go/internal/protocol"
	"github.com/fedi-e2ee/pkd-server-go/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPKDService_ProcessAddAuxData_WithValidation(t *testing.T) {
	ti, err := testutil.NewTestInstance(t)
	require.NoError(t, err)
	defer ti.Teardown()

	// Create a new PKDService with the SSHValidator enabled.
	// This means this server only accepts SSH public keys for AddAuxData messages.
	enabledValidators := []auxvalidator.AuxDataValidator{
		auxdata.NewSSHValidator(),
	}
	service := domain.NewPKDService(ti.Repo, enabledValidators)

	ctx := context.Background()
	actorID := "test@example.com"
	merkleRoot := "merkle-root"

	t.Run("valid data for registered type", func(t *testing.T) {
		msg := &protocol.AddAuxDataMessage{
			Actor:   actorID,
			AuxType: "ssh-v2",
			AuxData: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGC/Q+oNunkh9/LwV/KSl1/l+DEoM6l8f/2v6b4/d2rc agent@localhost",
		}

		aux, err := service.ProcessAddAuxData(ctx, msg, merkleRoot)
		require.NoError(t, err)
		assert.NotNil(t, aux)
		assert.Equal(t, msg.AuxType, aux.AuxType)
		assert.Equal(t, msg.AuxData, aux.AuxData)
	})

	t.Run("invalid data for registered type", func(t *testing.T) {
		msg := &protocol.AddAuxDataMessage{
			Actor:   actorID,
			AuxType: "ssh-v2",
			AuxData: "", // Invalid data
		}

		_, err := service.ProcessAddAuxData(ctx, msg, merkleRoot)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid ssh public key")
	})

	t.Run("unregistered type", func(t *testing.T) {
		msg := &protocol.AddAuxDataMessage{
			Actor:   actorID,
			AuxType: "some.other.type",
			AuxData: "any-data",
		}

		aux, err := service.ProcessAddAuxData(ctx, msg, merkleRoot)
		require.NoError(t, err)
		assert.NotNil(t, aux)
		assert.Equal(t, msg.AuxType, aux.AuxType)
		assert.Equal(t, msg.AuxData, aux.AuxData)
	})
}
