package lastpass

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestStringFormat(t *testing.T) {
	assert.Contains(t, Account{Username: "yoyo@gmail.com"}.String(), "yoyo@gmail.com")
}

func TestFailEncInvalidKeySize(t *testing.T) {
	acc := Account{Username: "yoyo@gmail.com"}
	vals, err := acc.encrypt(s2b("sd"))
	assert.Nil(t, vals)
	assert.Contains(t, err.Error(), "invalid key size 2")
	assert.Contains(t, err.Error(), "username")
}
