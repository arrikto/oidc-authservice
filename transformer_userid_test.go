package main

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecode(t *testing.T) {
	var transformer UserIDTransformer
	err := transformer.Decode(`[{"matches": "user@test\\.com", "replaces": ""}, {"matches": "test\\.com", "replaces": ""}]`)
	require.NoError(t, err, "Unexpected error")
	require.Len(t, transformer.rules, 2, "Should have 2 items")
}

func TestDecode_InvalidRegex(t *testing.T) {
	var transformer UserIDTransformer
	require.Panics(t, func() { transformer.Decode(`[{"matches": "[", "replaces": ""}]`) })
}

func TestDecode_InvalidJSON(t *testing.T) {
	var transformer UserIDTransformer
	err := transformer.Decode(`[{"matches": `)
	require.Error(t, err, "Should return error")
}

func TestDecode_InvalidJSONMatcher(t *testing.T) {
	var transformer UserIDTransformer
	err := transformer.Decode(`[{"matches": "test"}]`)
	require.Error(t, err, "Should return error")
}

func TestDecode_InvalidJSONFormat(t *testing.T) {
	var transformer UserIDTransformer
	err := transformer.Decode(`[{"what": "isThis"}]`)
	require.Error(t, err, "Should return error")
}

func TestTransform(t *testing.T) {
	transformer := &UserIDTransformer{
		rules: []userIDTransformationRule{
			&regexReplaceTransformationRule{
				matches:  regexp.MustCompile("user@domain\\.com"),
				replaces: "transformed",
			},
			&regexReplaceTransformationRule{
				matches:  regexp.MustCompile("@domain\\.com"),
				replaces: "",
			},
		},
	}
	var transformedID = transformer.Transform("user@domain.com")
	require.Equal(t, "transformed", transformedID, "Should change the UserID")

	transformedID = transformer.Transform("onlyUsername@domain.com")
	require.Equal(t, "onlyUsername", transformedID, "Should change the UserID")

	transformedID = transformer.Transform("user@anotherDomain.com")
	require.Equal(t, "user@anotherDomain.com", transformedID, "Should not change the UserID")
}
