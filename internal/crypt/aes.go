package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"crypto/rand"
	"bytes"
)

func Decrypt_aes256_cbc_plain(data []byte, encryptionKey []byte) []byte {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err.Error())
	}
	iv, in := data[:aes.BlockSize], data[aes.BlockSize:]
	dec := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(in))
	dec.CryptBlocks(out, in)
	return Pkcs7Unpad(out)
}

func Decrypt_aes256_cbc_base64(data []byte, encryptionKey []byte) []byte {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err.Error())
	}
	iv, in := DecodeBase64(data[:24]), DecodeBase64(data[24:])
	dec := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(in))
	dec.CryptBlocks(out, in)
	return Pkcs7Unpad(out)
}

func Decrypt_aes256_ecb_plain(data []byte, encryptionKey []byte) []byte {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err.Error())
	}
	dec := NewECBDecrypter(block)
	out := make([]byte, len(data))
	dec.CryptBlocks(out, data)
	return Pkcs7Unpad(out)
}

func Decrypt_aes256_ecb_base64(data []byte, encryptionKey []byte) []byte {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err.Error())
	}
	data = DecodeBase64(data)
	dec := NewECBDecrypter(block)
	out := make([]byte, len(data))
	dec.CryptBlocks(out, data)
	return Pkcs7Unpad(out)
}

func encrypt_aes256_cbc(plaintext, iv, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext = Pkcs7Pad(plaintext, block.BlockSize())

	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)
	return ciphertext
}

func Encrypt_aes256_cbc_base64(plaintext, key []byte) []byte {
	iv, _ := getIv()
	return encrypt_aes256_cbc_base64(plaintext, iv, key)
}

func encrypt_aes256_cbc_base64(plaintext, iv, key []byte) []byte {
	ciphertext := bytes.NewBufferString("!")
	ciphertext.Write(iv)
	ciphertext.Write(encrypt_aes256_cbc(plaintext, iv, key))
	return intBase64Encode(ciphertext.Bytes())
}

func getIv() ([]byte, int) {
	iv := make([]byte, aes.BlockSize)
	n, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		panic(err)
	}
	return iv, n
}
