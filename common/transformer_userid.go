package common

import (
	"encoding/json"
	"regexp"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// userIDTransformationRule represents a single transformation rule and
// encapsulates it's functionality. This is a generic interface that
// multiple rules can implement to expand the UserIDTransformer functionality.
type userIDTransformationRule interface {
	// isApplicable checks if the rule is relevant for the userID.
	isApplicable(userID string) bool
	// apply does the actual transformation to userID.
	apply(userID string) string
}

// UserIDTransformer holds the UserID transformation rules.
type UserIDTransformer struct {
	rules []userIDTransformationRule
}

// Transform modifies the UserID based on user provided rules. This method will
// search the rules in order, find the first that matches the userID and
// replace the match with the provided value. If no matching rule is found, it
// will return the original value.
// For example using the rules:
//   [
//     {"matches" : "user1@domain\\.com", "replaces": "anotherUser" },
//     {"matches" : "@domain\\.com", "replaces": "" }
//   ]
// The userID `user@domain.com` will be transformed to `anotherUser`
// based on the first rule.
// The userID `user2@domain.com` will be transformed to `user2` based
// on the second rule.
// The userID `user@other.com` will not be transformed and the original value
// will be returned.
func (uit *UserIDTransformer) Transform(userID string) string {
	// Check each rule.
	for _, rule := range uit.rules {
		if rule.isApplicable(userID) {
			// If the rule matches, apply the transformation.
			transformed := rule.apply(userID)
			log.WithFields(log.Fields{
				"originalID":    userID,
				"transformedID": transformed,
			}).Info("Transforming UserID")
			return transformed
		}
	}
	// If no rule matched, return the original value.
	return userID
}

// Decode creates a new UserIDTransformer using as input a JSON formatted
// string for rules initialization.
// The accepted JSON format is:
// {
//   [
//     {"matches": "regex", "replaces": "value"}
//   ]
// }
func (uit *UserIDTransformer) Decode(value string) error {
	var rules []userIDTransformationRule
	var config []map[string]*json.RawMessage
	// Unmarshal the JSON config to a list of objects.
	if err := json.Unmarshal([]byte(value), &config); err != nil {
		return err
	}
	for _, entry := range config {
		// Unmarshal a regexReplaceTransformationRule.
		if matches, ok := entry["matches"]; ok {
			if replaces, ok := entry["replaces"]; ok {
				var rule regexReplaceTransformationRule
				if err := json.Unmarshal(*replaces, &rule.replaces); err != nil {
					return err
				}
				var regex string
				if err := json.Unmarshal(*matches, &regex); err != nil {
					return err
				}
				rule.matches = regexp.MustCompile(regex)
				rules = append(rules, &rule)
			} else {
				// If the required fields are missing, return an error.
				return errors.Errorf("error unmarshalling UserID transformer" +
					" JSON config, 'replaces' field is missing.")
			}
		} else {
			// If no unmarshalling subtype is matched, return an error
			return errors.Errorf("error unmarshalling UserID transformer" +
				" JSON config, 'matches' field is missing.")
		}
	}
	*uit = UserIDTransformer{
		rules: rules,
	}
	return nil
}

/////////////////////////////////////////////////
//         Rules Implementations               //
/////////////////////////////////////////////////

// regexReplaceTransformationRule represents a single transformation rule that matches
// the userID with a regular expression and replaces the match with a predefined value.
type regexReplaceTransformationRule struct {
	matches  *regexp.Regexp
	replaces string
}

func (r *regexReplaceTransformationRule) isApplicable(userID string) bool {
	return r.matches.MatchString(userID)
}

func (r *regexReplaceTransformationRule) apply(userID string) string {
	return r.matches.ReplaceAllString(userID, r.replaces)
}
