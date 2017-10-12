package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"crypto/rand"
	"bytes"
	"github.com/pkg/errors"
)

func Decrypt_aes256_cbc_plain(data []byte, encryptionKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new cipher")
	}
	iv, in := data[:aes.BlockSize], data[aes.BlockSize:]
	dec := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(in))
	dec.CryptBlocks(out, in)
	return Pkcs7Unpad(out), nil
}

func Decrypt_aes256_cbc_base64(data []byte, encryptionKey []byte) ([]byte, error) {
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
	return Pkcs7Unpad(out), nil
}

func Decrypt_aes256_ecb_plain(data []byte, encryptionKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new cipher")
	}
	dec := NewECBDecrypter(block)
	out := make([]byte, len(data))
	dec.CryptBlocks(out, data)
	return Pkcs7Unpad(out), nil
}

func Decrypt_aes256_ecb_base64(data []byte, encryptionKey []byte) ([]byte, error) {
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
	return Pkcs7Unpad(out), nil
}

func encrypt_aes256_cbc(plaintext, iv, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new cipher")
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext = Pkcs7Pad(plaintext, block.BlockSize())

	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext, nil
}

func Encrypt_aes256_cbc_base64(plaintext, key []byte) ([]byte, error) {
	iv, _, err := getIv()
	if err != nil {
		return nil, err
	}

	ctext, err := encrypt_aes256_cbc_base64(plaintext, iv, key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to aes256cbc encrypt")
	}
	return ctext, nil
}

func encrypt_aes256_cbc_base64(plaintext, iv, key []byte) ([]byte, error) {
	ciphertext := bytes.NewBufferString("!")
	ciphertext.Write(iv)
	ctext, err := encrypt_aes256_cbc(plaintext, iv, key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to aes256cbc encrypt")
	}
	ciphertext.Write(ctext)
	return intBase64Encode(ciphertext.Bytes()), nil
}

func getIv() ([]byte, int, error) {
	iv := make([]byte, aes.BlockSize)
	n, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, -1, errors.Wrap(err, "failed to generate IV")
	}
	return iv, n, nil
}
