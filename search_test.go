package lastpass

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMatchFuncs(t *testing.T) {
	testCases := []struct {
		name    string
		val     string
		matcher string
		searchM SearchMethod
		match   bool
	}{
		{"substring url", "m.facebook.com", "facebook.com", SUBSTRINGSENSITIVE, true},
		{"substring not in url", "facebook.com", "facsebook.com", SUBSTRINGINSENSITIVE, false},
		{"substring in url", "https://stackoverflow.com/", "StackOverflow", SUBSTRINGINSENSITIVE, true},
		{"regex in url", "https://stackOverflow.com/", `(s|S)tack(O|o)verflow`, REGEX, true},
		{"case insens url", "youtube.com", "YouTube.com", CASEINSENSITVE, true},
		{"case sens ID", "8675309", "8675309", CASESENSITVE, true},
		{"case insens email", "gimmegimme@gmail.com", `@gmail.com`, CASEINSENSITVE, false},
		{"regex subdomains only", "m.cnn.com", `.+\.cnn\.com`, REGEX, true},
		{"regex no subdmomains", "fakenews.com", `^fakenews\.com`, REGEX, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(subT *testing.T) {
			actual := matchFuncs[tc.searchM](tc.val, tc.matcher)
			assert.Equal(subT, tc.match, actual, fmt.Sprintf("%v", tc))
		})
	}
}

func TestAccountGetValue(t *testing.T) {
	account := Account{
		Id:       "8675309",
		Username: "followmeontwitter",
		Url:      "https://twitter.com/",
		Name:     "Twitter",
	}
	assert.Equal(t, account.Id, getValue(account, ID))
	assert.Equal(t, account.Username, getValue(account, USERNAME))
	assert.Equal(t, account.Url, getValue(account, URL))
	assert.Equal(t, account.Name, getValue(account, NAME))
	assert.Equal(t, account.Id, getValue(account, Field(uint32(65165165))))
}
