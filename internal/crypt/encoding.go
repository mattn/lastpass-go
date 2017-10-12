package crypt

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
)

func Base64Encode(data []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(data))
}

func DecodeBase64(b []byte) ([]byte, error) {
	d := make([]byte, len(b))
	n, err := base64.StdEncoding.Decode(d, b)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode b64")
	}
	return d[:n], nil
}

// intermediate base 64 encode
func intBase64Encode(data []byte) []byte {
	dLen := len(data)

	if dLen >= 33 && data[0] == '!' && dLen%16 == 1 {
		// "!%s|%s"
		iv := Base64Encode(data[1 : aes.BlockSize+1])
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

func DecodeHex(b []byte) ([]byte, error) {
	d := make([]byte, len(b))
	n, err := hex.Decode(d, b)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode hex")
	}
	return d[:n], nil
}
