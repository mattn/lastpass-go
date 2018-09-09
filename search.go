package lastpass

import (
	"regexp"
	"strings"
)

// Field holds the search criteria.
type Field uint32

// SearchMethod holds the search method.
type SearchMethod uint32

// Account fields
const (
	FieldID Field = iota
	FieldName
	FieldURL
	FieldUsername
)

// Match function types
const (
	SearchMethodCaseSensitive SearchMethod = iota
	SearchMethodCaseInsensitive
	SearchMethodRegex
	SearchMethodSubstringSensitive
	SearchMethodSubstringInsensitive
)

type matchFunc func(fieldValue string, value string) bool

var matchFuncs = map[SearchMethod]matchFunc{
	SearchMethodCaseSensitive:        exactMatch(true),
	SearchMethodCaseInsensitive:      exactMatch(false),
	SearchMethodSubstringSensitive:   substringMatch(true),
	SearchMethodSubstringInsensitive: substringMatch(false),
	SearchMethodRegex:                regexMatch,
}

// regexMatch matches a fieldValue with a given pattern
func regexMatch(fieldValue, pattern string) bool {
	match, _ := regexp.MatchString(pattern, fieldValue)
	return match
}

// exactMatch matches a fieldValue with a given match
// value through string equality
func exactMatch(caseSensitive bool) func(fieldValue, matchValue string) bool {
	return func(fieldValue, matchValue string) bool {
		if !caseSensitive {
			fieldValue = strings.ToLower(fieldValue)
			matchValue = strings.ToLower(matchValue)
		}

		return fieldValue == matchValue
	}
}

// substringMatch matches a fieldValue contains
// the given substring
func substringMatch(caseSensitive bool) func(fieldValue, matchValue string) bool {
	return func(fieldValue, matchValue string) bool {
		if !caseSensitive {
			fieldValue = strings.ToLower(fieldValue)
			matchValue = strings.ToLower(matchValue)
		}

		return strings.Contains(fieldValue, matchValue)
	}
}

func getValue(account Account, field Field) string {
	switch field {
	case FieldID:
		return account.ID
	case FieldName:
		return account.Name
	case FieldURL:
		return account.URL
	case FieldUsername:
		return account.Username
	default:
		return account.ID
	}
}
