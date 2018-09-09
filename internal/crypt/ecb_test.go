package crypt

import (
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewECBEncryptor(t *testing.T) {
	//given
	plaintext := []byte{0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255}
	kek := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	block, _ := aes.NewCipher(kek)

	test := make([]byte, len(plaintext))

	//when
	enc := NewECBEncrypter(block)
	enc.CryptBlocks(test, plaintext)
	assert.Equal(t, block.BlockSize(), enc.BlockSize())

	//then
	assert.Equal(t, test, []byte{105, 196, 224, 216, 106, 123, 4, 48, 216, 205, 183, 128, 112, 180, 197, 90})
}
func TestNewECBDecryptor(t *testing.T) {
	//given
	ciphertext := []byte{105, 196, 224, 216, 106, 123, 4, 48, 216, 205, 183, 128, 112, 180, 197, 90}
	kek := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	block, _ := aes.NewCipher(kek)

	test := make([]byte, len(ciphertext))

	//when
	dec := NewECBDecrypter(block)
	dec.CryptBlocks(test, ciphertext)

	assert.Equal(t, block.BlockSize(), dec.BlockSize())

	//then
	assert.Equal(t, test, []byte{0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255})
}
