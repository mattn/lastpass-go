package crypt

import (
	"testing"
	"crypto/sha256"
	"github.com/stretchr/testify/assert"
	"crypto/aes"
)

func TestEncrypt_aes256_cbc(t *testing.T) {
	key := DecodeHex([]byte("05d49692b755f99c45012310418efeeeebfd466892540f27acf9a31a326d6123"))
	assert.Equal(t, sha256.Size, len(key))

	iv := DecodeHex([]byte("a07c8d27359fdf50c66675c3e07bd5e1"))
	assert.Equal(t, len(iv), aes.BlockSize)

	ciphertext := encrypt_aes256_cbc([]byte("hello world"), iv, key)
	assert.Equal(t, "99b7bbf92427f996a4de6a1858dea1d9", string(EncodeHex(ciphertext)))
}

func TestEncrypt_aes256_cbc_base64(t *testing.T) {
	plaintext := []byte("hello world")
	key := DecodeHex([]byte("2B42B93B2439B9CB9EB9D12349234AABCD429AB238A234957929274D92EF9234"))
	assert.Equal(t, sha256.Size, len(key))

	iv := DecodeHex([]byte("ABCD12340312341728304697DEF34134"))
	assert.Equal(t, len(iv), aes.BlockSize)

	b64 := string(encrypt_aes256_cbc_base64(plaintext, iv, key))
	assert.Equal(t, "!q80SNAMSNBcoMEaX3vNBNA==|GSG5M1Zs8mymkZLusq/67g==", b64)
}


func TestEncrypt_aes256_cbc_base64Long(t *testing.T) {
	plaintext := []byte("kjnsdfvkljnsdfkjdfkjnvsdfkjnvsdkfjnvslkdjfnklvjsdnfkvljsndfvdkjf")
	key := DecodeHex([]byte("2B42B93B2439B9CB9EB9D12349234AABCD429AB238A234957929274D92EF9234"))
	assert.Equal(t, sha256.Size, len(key))

	iv := DecodeHex([]byte("ABCD12340312341728304697DEF34134"))
	assert.Equal(t, len(iv), aes.BlockSize)

	b64 := string(encrypt_aes256_cbc_base64(plaintext, iv, key))
	assert.Equal(t, "!q80SNAMSNBcoMEaX3vNBNA==|/CoDSFDuGHcwYomJsQbwep3tEkkYTeiKYFqxsMWNlcC7LlWqIcfD03OAvlBZZUz/sr0lxSsRT1Ua/4+Lh8IyAXYT0vf2J3pVQxsuhXBSZYg=", b64)
}
func TestEncrypt_aes256_cbc_base64Short(t *testing.T) {
	plaintext := []byte("r23p4jsdaskjldfnaslkmdjfmnasdfsdjnfalksdjfnmlaksjdnfmaksnjdfmmr")
	key := DecodeHex([]byte("2B42B93B2439B9CB9EB9D12349234AABCD429AB238A234957929274D92EF9234"))
	assert.Equal(t, sha256.Size, len(key))

	iv := DecodeHex([]byte("ABCD12340312341728304697DEF34134"))
	assert.Equal(t, len(iv), aes.BlockSize)

	b64 := string(encrypt_aes256_cbc_base64(plaintext, iv, key))
	assert.Equal(t, "!q80SNAMSNBcoMEaX3vNBNA==|VPjgcgT1ZlQyX9XyI0jQ7j+8wJLDM7aRKGtaHpqknGepjFk/bMUe54bYskzmhpkiMzYTqhqkBjMO9VZ55Ky4Yw==", b64)
}
