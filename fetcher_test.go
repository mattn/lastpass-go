package lastpass

import (
	"testing"
	"github.com/while-loop/lastpass-go/internal/crypt"
	"github.com/stretchr/testify/assert"
)

func TestIterationCount1(t *testing.T) {
	expected := []byte("65333739643937326333656235393537396162653338363464383530623566353439313135343461646661326461663966623533633035643330636463393835")
	hash := crypt.EncodeHex(makeHash("username", "password", 1))
	assert.Equal(t, expected, hash)
}

func TestIterationCount2(t *testing.T) {
	expected := []byte("38363361663762326636373131386162643139623936313265343233313661363033666664646437666330623730353334313936356331653839643864333565")
	hash := crypt.EncodeHex(makeHash("username", "password", 2))
	assert.Equal(t, expected, hash)
}
