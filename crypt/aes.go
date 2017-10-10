package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/while-loop/lastpass-go/ecb"
	"io"
	"crypto/rand"
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
	dec := ecb.NewECBDecrypter(block)
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
	dec := ecb.NewECBDecrypter(block)
	out := make([]byte, len(data))
	dec.CryptBlocks(out, data)
	return Pkcs7Unpad(out)
}

func EncryptAes256Cbc(plaintext, key []byte) []byte {
	pLen := len(plaintext)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	cLen := 0
	ciphertext := make([]byte, pLen+aes.BlockSize*2+1)
	ciphertext[0] = '!'
	cLen++

	iv := ciphertext[1:aes.BlockSize+1]
	n, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		panic(err)
	}
	cLen += n

	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext = Pkcs7Pad(plaintext, block.BlockSize())

	mode.CryptBlocks(ciphertext[cLen:], plaintext)

	return intBase64Encode(ciphertext)
}
