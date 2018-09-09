package lastpass

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchFuncs(t *testing.T) {
	testCases := []struct {
		name    string
		val     string
		matcher string
		searchM SearchMethod
		match   bool
	}{
		{"substring url", "m.facebook.com", "facebook.com", SearchMethodSubstringSensitive, true},
		{"substring not in url", "facebook.com", "facsebook.com", SearchMethodSubstringInsensitive, false},
		{"substring in url", "https://stackoverflow.com/", "StackOverflow", SearchMethodSubstringInsensitive, true},
		{"regex in url", "https://stackOverflow.com/", `(s|S)tack(O|o)verflow`, SearchMethodRegex, true},
		{"case insens url", "youtube.com", "YouTube.com", SearchMethodCaseInsensitive, true},
		{"case sens ID", "8675309", "8675309", SearchMethodCaseSensitive, true},
		{"case insens email", "gimmegimme@gmail.com", `@gmail.com`, SearchMethodCaseSensitive, false},
		{"regex subdomains only", "m.cnn.com", `.+\.cnn\.com`, SearchMethodRegex, true},
		{"regex no subdmomains", "fakenews.com", `^fakenews\.com`, SearchMethodRegex, true},
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
		ID:       "8675309",
		Username: "followmeontwitter",
		URL:      "https://twitter.com/",
		Name:     "Twitter",
	}
	assert.Equal(t, account.ID, getValue(account, FieldID))
	assert.Equal(t, account.Username, getValue(account, FieldUsername))
	assert.Equal(t, account.URL, getValue(account, FieldURL))
	assert.Equal(t, account.Name, getValue(account, FieldName))
	assert.Equal(t, account.ID, getValue(account, Field(uint32(65165165))))
}
