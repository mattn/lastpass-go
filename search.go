package lastpass

import (
	"regexp"
	"strings"
)

type Field uint32
type SearchMethod uint32

const (
	// Account fields
	Id       Field = iota
	Name
	Url
	Username

	// Match function types
	CaseSensitive       SearchMethod = iota
	CaseInsensitive
	Regex
	SubstringSensitive
	SubstringInsensitive
)

type matchFunc func(fieldValue string, value string) bool

var matchFuncs = map[SearchMethod]matchFunc{
	CaseSensitive:        exactMatch(true),
	CaseInsensitive:      exactMatch(false),
	SubstringSensitive:   substringMatch(true),
	SubstringInsensitive: substringMatch(false),
	Regex:                regexMatch,
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
	case Id:
		return account.Id
	case Name:
		return account.Name
	case Url:
		return account.Url
	case Username:
		return account.Username
	default:
		return account.Id
	}
}
