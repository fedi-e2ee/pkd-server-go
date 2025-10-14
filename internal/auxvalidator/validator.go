package auxvalidator

// AuxDataValidator defines the interface for validating auxiliary data.
type AuxDataValidator interface {
	// Validate checks if the given data is valid for the specific AuxType.
	Validate(data string) error
	// Type returns the AuxType that this validator handles.
	Type() string
}
