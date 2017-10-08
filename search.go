package lastpass

import (
	"regexp"
	"strings"
)

type Field uint32
type SearchMethod uint32

const (
	// Account fields
	ID Field = iota
	NAME
	URL
	USERNAME

	// Match function types
	CASESENSITVE SearchMethod = iota
	CASEINSENSITVE
	REGEX
	SUBSTRINGSENSITIVE
	SUBSTRINGINSENSITIVE
)

type matchFunc func(fieldValue string, value string) bool

var matchFuncs = map[SearchMethod]matchFunc{
	CASESENSITVE:         exactMatch(true),
	CASEINSENSITVE:       exactMatch(false),
	SUBSTRINGSENSITIVE:   substringMatch(true),
	SUBSTRINGINSENSITIVE: substringMatch(false),
	REGEX:                regexMatch,
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
	case ID:
		return account.Id
	case NAME:
		return account.Name
	case URL:
		return account.Url
	case USERNAME:
		return account.Username
	default:
		return account.Id
	}
}
