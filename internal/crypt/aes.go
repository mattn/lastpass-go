package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/pkg/errors"
)

// DecryptAES256CBCPlain ...
func DecryptAES256CBCPlain(data []byte, encryptionKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new cipher")
	}
	iv, in := data[:aes.BlockSize], data[aes.BlockSize:]
	dec := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(in))
	dec.CryptBlocks(out, in)
	return PKCS7Unpad(out), nil
}

// DecryptAES256CBCBase64 ...
func DecryptAES256CBCBase64(data []byte, encryptionKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new cipher")
	}
	iv, err := DecodeBase64(data[:24])
	if err != nil {
		return nil, errors.Wrap(err, "failed to b64 decode IV")
	}
	in, err := DecodeBase64(data[24:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to b64 decode in data")
	}
	dec := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(in))
	dec.CryptBlocks(out, in)
	return PKCS7Unpad(out), nil
}

// DecryptAES256ECBPlain ...
func DecryptAES256ECBPlain(data []byte, encryptionKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new cipher")
	}
	dec := NewECBDecrypter(block)
	out := make([]byte, len(data))
	dec.CryptBlocks(out, data)
	return PKCS7Unpad(out), nil
}

// DecryptAES256ECBBase64 ...
func DecryptAES256ECBBase64(data []byte, encryptionKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new cipher")
	}
	data, err = DecodeBase64(data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to b64 decode aes256 data")
	}

	dec := NewECBDecrypter(block)
	out := make([]byte, len(data))
	dec.CryptBlocks(out, data)
	return PKCS7Unpad(out), nil
}

func encryptAES256CBC(plaintext, iv, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new cipher")
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext = PKCS7Pad(plaintext, block.BlockSize())

	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

// EncryptAES256CBCBase64 ...
func EncryptAES256CBCBase64(plaintext, key []byte) ([]byte, error) {
	iv, _, err := getIV()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get iv to encode aes256")
	}

	ctext, err := encryptAES256CBCBase64(plaintext, iv, key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to aes256cbc encrypt")
	}
	return ctext, nil
}

func encryptAES256CBCBase64(plaintext, iv, key []byte) ([]byte, error) {
	ciphertext := bytes.NewBufferString("!")
	ciphertext.Write(iv)
	ctext, err := encryptAES256CBC(plaintext, iv, key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to aes256cbc encrypt")
	}
	ciphertext.Write(ctext)
	return intBase64Encode(ciphertext.Bytes()), nil
}

func getIV() ([]byte, int, error) {
	iv := make([]byte, aes.BlockSize)
	n, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, -1, errors.Wrap(err, "failed to generate IV")
	}
	return iv, n, nil
}
