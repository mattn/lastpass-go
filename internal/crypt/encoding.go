package crypt

import (
	"encoding/base64"
	"bytes"
	"encoding/hex"
	"crypto/aes"
	"fmt"
)

func Base64Encode(data []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(data))
}

func DecodeBase64(b []byte) []byte {
	d := make([]byte, len(b))
	n, _ := base64.StdEncoding.Decode(d, b)
	return d[:n]
}

// intermediate base 64 encode
func intBase64Encode(data []byte) []byte {
	dLen := len(data)

	if dLen >= 33 && data[0] == '!' && dLen%16 == 1 {
		// "!%s|%s"
		iv := Base64Encode(data[1:aes.BlockSize+1])
		d := Base64Encode(data[1+aes.BlockSize:])
		return []byte(fmt.Sprintf("!%s|%s", iv, d))
	}

	return Base64Encode(data)
}

func Pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func Pkcs7Unpad(data []byte) []byte {
	size := len(data)
	unpadding := int(data[size-1])
	return data[:(size - unpadding)]
}

func EncodeHex(b []byte) []byte {
	d := make([]byte, len(b)*2)
	n := hex.Encode(d, b)
	return d[:n]
}

func DecodeHex(b []byte) []byte {
	d := make([]byte, len(b))
	n, _ := hex.Decode(d, b)
	return d[:n]
}
