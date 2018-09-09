package crypt

import (
	"crypto/aes"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncrypt_aes256_cbc(t *testing.T) {
	key, err := DecodeHex([]byte("05d49692b755f99c45012310418efeeeebfd466892540f27acf9a31a326d6123"))
	assert.NoError(t, err)
	assert.Equal(t, sha256.Size, len(key))

	iv, err := DecodeHex([]byte("a07c8d27359fdf50c66675c3e07bd5e1"))
	assert.NoError(t, err)
	assert.Equal(t, len(iv), aes.BlockSize)

	ciphertext, err := encrypt_aes256_cbc([]byte("hello world"), iv, key)
	assert.NoError(t, err)
	assert.Equal(t, "99b7bbf92427f996a4de6a1858dea1d9", string(EncodeHex(ciphertext)))
}

func TestEncrypt_aes256_cbc_base64(t *testing.T) {
	plaintext := []byte("hello world")
	key, err := DecodeHex([]byte("2B42B93B2439B9CB9EB9D12349234AABCD429AB238A234957929274D92EF9234"))
	assert.NoError(t, err)
	assert.Equal(t, sha256.Size, len(key))

	iv, err := DecodeHex([]byte("ABCD12340312341728304697DEF34134"))
	assert.NoError(t, err)
	assert.Equal(t, len(iv), aes.BlockSize)

	ctext, err := encrypt_aes256_cbc_base64(plaintext, iv, key)
	assert.NoError(t, err)
	assert.Equal(t, "!q80SNAMSNBcoMEaX3vNBNA==|GSG5M1Zs8mymkZLusq/67g==", string(ctext))
}

func TestEncrypt_aes256_cbc_base64Long(t *testing.T) {
	plaintext := []byte("kjnsdfvkljnsdfkjdfkjnvsdfkjnvsdkfjnvslkdjfnklvjsdnfkvljsndfvdkjf")
	key, err := DecodeHex([]byte("2B42B93B2439B9CB9EB9D12349234AABCD429AB238A234957929274D92EF9234"))
	assert.NoError(t, err)
	assert.Equal(t, sha256.Size, len(key))

	iv, err := DecodeHex([]byte("ABCD12340312341728304697DEF34134"))
	assert.NoError(t, err)
	assert.Equal(t, len(iv), aes.BlockSize)

	ctext, err := encrypt_aes256_cbc_base64(plaintext, iv, key)
	assert.NoError(t, err)
	assert.Equal(t, "!q80SNAMSNBcoMEaX3vNBNA==|/CoDSFDuGHcwYomJsQbwep3tEkkYTeiKYFqxs"+
		"MWNlcC7LlWqIcfD03OAvlBZZUz/sr0lxSsRT1Ua/4+Lh8IyAXYT0vf2J3pVQxsuhXBSZYg=", string(ctext))
}
func TestEncrypt_aes256_cbc_base64Short(t *testing.T) {
	plaintext := []byte("r23p4jsdaskjldfnaslkmdjfmnasdfsdjnfalksdjfnmlaksjdnfmaksnjdfmmr")
	key, err := DecodeHex([]byte("2B42B93B2439B9CB9EB9D12349234AABCD429AB238A234957929274D92EF9234"))
	assert.NoError(t, err)
	assert.Equal(t, sha256.Size, len(key))

	iv, err := DecodeHex([]byte("ABCD12340312341728304697DEF34134"))
	assert.NoError(t, err)
	assert.Equal(t, len(iv), aes.BlockSize)

	ctext, err := encrypt_aes256_cbc_base64(plaintext, iv, key)
	assert.NoError(t, err)
	assert.Equal(t, "!q80SNAMSNBcoMEaX3vNBNA==|VPjgcgT1ZlQyX9XyI0jQ7j+8wJLDM7aR"+
		"KGtaHpqknGepjFk/bMUe54bYskzmhpkiMzYTqhqkBjMO9VZ55Ky4Yw==", string(ctext))
}
