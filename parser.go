package lastpass

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"github.com/while-loop/lastpass-go/ecb"
	"io"
	"crypto/rand"
	"fmt"
	"crypto/hmac"
	"crypto/sha256"
)

func chunkIdFromBytes(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func chunkIdFromString(s string) uint32 {
	b := []byte(s)
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func readId(r io.Reader) (uint32, error) {
	var b [4]byte
	_, err := r.Read(b[:])
	if err != nil {
		return 0, err
	}
	return chunkIdFromBytes(b), nil
}

func readSize(r io.Reader) (uint32, error) {
	var b [4]byte
	_, err := r.Read(b[:])
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func readItem(r io.Reader) ([]byte, error) {
	size, err := readSize(r)
	if err != nil {
		return nil, err
	}
	b := make([]byte, size)
	n, err := r.Read(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}

func skipItem(r io.Reader) error {
	readSize, err := readSize(r)
	if err != nil {
		return err
	}
	b := make([]byte, readSize)
	_, err = r.Read(b)
	if err != nil {
		return err
	}
	return nil
}

func extractChunks(r io.Reader, filter []uint32) (map[uint32][][]byte, error) {
	chunks := map[uint32][][]byte{}
	for {
		chunkId, err := readId(r)
		if err != nil {
			if err == io.EOF {
				break
			}
		}

		payload, err := readItem(r)
		if err != nil {
			return nil, err
		}

		found := false
		for _, filterId := range filter {
			if filterId == chunkId {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		if _, ok := chunks[chunkId]; !ok {
			chunks[chunkId] = [][]byte{payload}
		} else {
			chunks[chunkId] = append(chunks[chunkId], payload)
		}
	}
	return chunks, nil
}

func parseAccount(r io.Reader, encryptionKey []byte) (*Account, error) {
	// id, plain
	id, err := readItem(r)
	if err != nil {
		return nil, err
	}

	// name, crypt
	name, err := readItem(r)
	if err != nil {
		return nil, err
	}

	// group, crpyt
	group, err := readItem(r)
	if err != nil {
		return nil, err
	}

	// url, hex
	url, err := readItem(r)
	if err != nil {
		return nil, err
	}

	// note, crypt
	notes, err := readItem(r)
	if err != nil {
		return nil, err
	}

	// fav, bool
	// share, _
	for i := 0; i < 2; i++ {
		skipItem(r)
	}

	// username, crypt
	username, err := readItem(r)
	if err != nil {
		return nil, err
	}

	// password, crypt
	password, err := readItem(r)
	if err != nil {
		return nil, err
	}

	return &Account{
		string(id),
		string(decryptAES256(name, encryptionKey)),
		string(decryptAES256(username, encryptionKey)),
		string(decryptAES256(password, encryptionKey)),
		string(decodeHex(url)),
		string(decryptAES256(group, encryptionKey)),
		string(decryptAES256(notes, encryptionKey))}, nil
}

func encodeHex(b []byte) []byte {
	d := make([]byte, len(b)*2)
	n := hex.Encode(d, b)
	return d[:n]
}

func decodeHex(b []byte) []byte {
	d := make([]byte, len(b))
	n, _ := hex.Decode(d, b)
	return d[:n]
}

func decodeBase64(b []byte) []byte {
	d := make([]byte, len(b))
	n, _ := base64.StdEncoding.Decode(d, b)
	return d[:n]
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func pkcs7Unpad(data []byte) []byte {
	size := len(data)
	unpadding := int(data[size-1])
	return data[:(size - unpadding)]
}

func decryptBuffer(data, key []byte) []byte {
	// ciphertext =IV  | aes-256-cbc(plaintext, key)
	// authenticated-ciphertext = HMAC-SHA256(ciphertext, key) | ciphertext

	ciphertext := data[sha256.Size:]
	givenDigest := data[:sha256.Size]
	h := hmac.New(sha256.New, key)
	fmt.Println(h.Write(ciphertext))
	calcdDigest := h.Sum(nil)

	if !hmac.Equal(calcdDigest, givenDigest) {
		panic(fmt.Errorf("payload signature check failed"))
	}

	return decrypt_aes256_cbc_plain(ciphertext, key)
}

func decrypt_aes256_cbc_plain(data []byte, encryptionKey []byte) []byte {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err.Error())
	}
	iv, in := data[:aes.BlockSize], data[aes.BlockSize:]
	dec := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(in))
	dec.CryptBlocks(out, in)
	return pkcs7Unpad(out)
}

func decrypt_aes256_cbc_base64(data []byte, encryptionKey []byte) []byte {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err.Error())
	}
	iv, in := decodeBase64(data[:24]), decodeBase64(data[24:])
	dec := cipher.NewCBCDecrypter(block, iv)
	out := make([]byte, len(in))
	dec.CryptBlocks(out, in)
	return pkcs7Unpad(out)
}

func decrypt_aes256_ecb_plain(data []byte, encryptionKey []byte) []byte {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err.Error())
	}
	dec := ecb.NewECBDecrypter(block)
	out := make([]byte, len(data))
	dec.CryptBlocks(out, data)
	return pkcs7Unpad(out)
}

func decrypt_aes256_ecb_base64(data []byte, encryptionKey []byte) []byte {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		panic(err.Error())
	}
	data = decodeBase64(data)
	dec := ecb.NewECBDecrypter(block)
	out := make([]byte, len(data))
	dec.CryptBlocks(out, data)
	return pkcs7Unpad(out)
}

func decryptAES256(data []byte, encryptionKey []byte) string {
	size := len(data)
	size16 := size % 16
	size64 := size % 64

	switch {
	case size == 0:
		return ""
	case size16 == 0:
		return string(decrypt_aes256_ecb_plain(data, encryptionKey))
	case size64 == 0 || size64 == 24 || size64 == 44:
		return string(decrypt_aes256_ecb_base64(data, encryptionKey))
	case size16 == 1:
		return string(decrypt_aes256_cbc_plain(data[1:], encryptionKey))
	case size64 == 6 || size64 == 26 || size64 == 50:
		return string(decrypt_aes256_cbc_base64(data, encryptionKey))
	}
	panic("Input doesn't seem to be AES-256 encrypted")
}

func encryptAes256Cbc(plaintext, key []byte) []byte {
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
	plaintext = pkcs7Pad(plaintext, block.BlockSize())

	mode.CryptBlocks(ciphertext[cLen:], plaintext)

	return intBase64Encode(ciphertext)
}

// intermediate base 64 encode
func intBase64Encode(data []byte) []byte {
	dLen := len(data)

	if dLen >= 33 && data[0] == '!' && dLen%16 == 1 {
		// "!%s|%s"
		offset := 1 + aes.BlockSize
		iv := base64Encode(data[1:offset])
		d := base64Encode(data[offset:])
		return []byte(fmt.Sprintf("!%s|%s", iv, d))
	}

	return base64Encode(data)
}

func base64Encode(data []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(data))
}
