package protocol

import (
	"encoding/json"
	"fmt"
)

// unmarshalWithChecks is a helper function that first unmarshals JSON data into
// a map to check for the presence of required fields. If all required fields
// are present, it then unmarshals the data into the target struct.
func unmarshalWithChecks(data []byte, v interface{}, requiredFields []string) error {
	// First, unmarshal into a map to check for required fields.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal for field check: %w", err)
	}

	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			return fmt.Errorf("missing required field: %s", field)
		}
	}

	// If all checks pass, unmarshal into the actual struct.
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("failed to unmarshal into target struct: %w", err)
	}

	return nil
}

// UnmarshalJSON implements custom unmarshaling logic for AddKeyMessage to
// enforce that all required fields are present.
func (m *AddKeyMessage) UnmarshalJSON(data []byte) error {
	type Alias AddKeyMessage
	aux := &struct{ *Alias }{Alias: (*Alias)(m)}
	return unmarshalWithChecks(data, aux, []string{"actor", "time", "public-key"})
}

// UnmarshalJSON implements custom unmarshaling logic for RevokeKeyMessage.
func (m *RevokeKeyMessage) UnmarshalJSON(data []byte) error {
	type Alias RevokeKeyMessage
	aux := &struct{ *Alias }{Alias: (*Alias)(m)}
	return unmarshalWithChecks(data, aux, []string{"actor", "time", "public-key"})
}

// UnmarshalJSON implements custom unmarshaling logic for RevokeKeyThirdPartyMessage.
func (m *RevokeKeyThirdPartyMessage) UnmarshalJSON(data []byte) error {
	type Alias RevokeKeyThirdPartyMessage
	aux := &struct{ *Alias }{Alias: (*Alias)(m)}
	return unmarshalWithChecks(data, aux, []string{"action", "revocation-token"})
}

// UnmarshalJSON implements custom unmarshaling logic for MoveIdentityMessage.
func (m *MoveIdentityMessage) UnmarshalJSON(data []byte) error {
	type Alias MoveIdentityMessage
	aux := &struct{ *Alias }{Alias: (*Alias)(m)}
	return unmarshalWithChecks(data, aux, []string{"old-actor", "new-actor", "time"})
}

// UnmarshalJSON implements custom unmarshaling logic for BurnDownMessage.
func (m *BurnDownMessage) UnmarshalJSON(data []byte) error {
	type Alias BurnDownMessage
	aux := &struct{ *Alias }{Alias: (*Alias)(m)}
	return unmarshalWithChecks(data, aux, []string{"actor", "operator", "time"})
}

// UnmarshalJSON implements custom unmarshaling logic for FireproofMessage.
func (m *FireproofMessage) UnmarshalJSON(data []byte) error {
	type Alias FireproofMessage
	aux := &struct{ *Alias }{Alias: (*Alias)(m)}
	return unmarshalWithChecks(data, aux, []string{"actor", "time"})
}

// UnmarshalJSON implements custom unmarshaling logic for UndoFireproofMessage.
func (m *UndoFireproofMessage) UnmarshalJSON(data []byte) error {
	type Alias UndoFireproofMessage
	aux := &struct{ *Alias }{Alias: (*Alias)(m)}
	return unmarshalWithChecks(data, aux, []string{"actor", "time"})
}

// UnmarshalJSON implements custom unmarshaling logic for AddAuxDataMessage.
func (m *AddAuxDataMessage) UnmarshalJSON(data []byte) error {
	type Alias AddAuxDataMessage
	aux := &struct{ *Alias }{Alias: (*Alias)(m)}
	return unmarshalWithChecks(data, aux, []string{"actor", "aux-type", "aux-data", "time"})
}

// UnmarshalJSON implements custom unmarshaling logic for RevokeAuxDataMessage.
func (m *RevokeAuxDataMessage) UnmarshalJSON(data []byte) error {
	type Alias RevokeAuxDataMessage
	aux := &struct{ *Alias }{Alias: (*Alias)(m)}
	// aux-data and aux-id are optional, but at least one must be present.
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if _, ok := raw["aux-data"]; !ok {
		if _, ok := raw["aux-id"]; !ok {
			return fmt.Errorf("at least one of 'aux-data' or 'aux-id' must be present")
		}
	}
	return unmarshalWithChecks(data, aux, []string{"actor", "aux-type", "time"})
}

// UnmarshalJSON implements custom unmarshaling logic for QueryMessage.
func (m *QueryMessage) UnmarshalJSON(data []byte) error {
	type Alias QueryMessage
	aux := &struct{ *Alias }{Alias: (*Alias)(m)}
	return unmarshalWithChecks(data, aux, []string{"actor"})
}

// UnmarshalJSON implements custom unmarshaling logic for CheckpointMessage.
func (m *CheckpointMessage) UnmarshalJSON(data []byte) error {
	type Alias CheckpointMessage
	aux := &struct{ *Alias }{Alias: (*Alias)(m)}
	return unmarshalWithChecks(data, aux, []string{"time", "from-directory", "from-root", "from-public-key", "to-directory", "to-validated-root"})
}
