package common

import (
	"encoding"
	"encoding/json"
	"fmt"
)

// ProtectedString is a type for security-ProtectedString fields.
// It hides its value when printed or marshalled to JSON.
// Used to hide ProtectedString fields from loggers.
type ProtectedString struct {
	value *string
}

var message = "<protected>"

func NewProtectedString(val string) *ProtectedString {
	return &ProtectedString{
		value: &val,
	}
}

// Reveal returns the secret value.
func (p *ProtectedString) Reveal() string {
	return *p.value
}

// String returns the string representation of the type. Override it to avoid
// logging the secret value.
func (p *ProtectedString) String() string {
	return message
}

var _ fmt.Stringer = (*ProtectedString)(nil)

// MarshalJSON returns the JSON representation of the type. Many loggers will
// log JSON representation of types. Override it to avoid logging the secret
// value.
func (p *ProtectedString) MarshalJSON() ([]byte, error) {
	return json.Marshal(&message)
}

var _ json.Marshaler = (*ProtectedString)(nil)

// UnmarshalText can unmarshal a textual representation of a ProtectedString.
// Needed for use with the envconfig library:
// https://github.com/kelseyhightower/envconfig
func (p *ProtectedString) UnmarshalText(text []byte) error {
	val := string(text)
	p.value = &val
	return nil
}

var _ encoding.TextUnmarshaler = (*ProtectedString)(nil)
