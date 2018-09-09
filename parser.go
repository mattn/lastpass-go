package lastpass

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	lcrypt "github.com/djui/lastpass-go/internal/crypt"
	"github.com/pkg/errors"
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
	sr := stickyReader{}

	id := sr.readItem(r)       // id, plain
	name := sr.readItem(r)     // name, crypt
	group := sr.readItem(r)    // group, crpyt
	url := sr.readItem(r)      // url, hex
	notes := sr.readItem(r)    // note, crypt
	sr.skipItem(r)             // fav, bool
	sr.skipItem(r)             // share, _
	username := sr.readItem(r) // username, crypt
	password := sr.readItem(r) // password, crypt
	if sr.hasErr() {
		return nil, sr.err
	}

	sr = stickyReader{}
	acc := &Account{
		string(id),
		sr.decryptAES256(name, encryptionKey),
		sr.decryptAES256(username, encryptionKey),
		sr.decryptAES256(password, encryptionKey),
		sr.DecodeHex(url),
		sr.decryptAES256(group, encryptionKey),
		sr.decryptAES256(notes, encryptionKey)}
	if sr.hasErr() {
		return nil, errors.Wrap(sr.err, "failed to decrypt account")
	}
	return acc, nil
}

func decryptBuffer(data, key []byte) ([]byte, error) {
	// used to decrypt session token
	// ciphertext =IV  | aes-256-cbc(plaintext, key)
	// authenticated-ciphertext = HMAC-SHA256(ciphertext, key) | ciphertext

	ciphertext := data[sha256.Size:]
	givenDigest := data[:sha256.Size]
	h := hmac.New(sha256.New, key)
	h.Write(ciphertext)
	calcdDigest := h.Sum(nil)

	if !hmac.Equal(calcdDigest, givenDigest) {
		return nil, fmt.Errorf("payload signature check failed")
	}

	return lcrypt.Decrypt_aes256_cbc_plain(ciphertext, key)
}

func decryptAES256(data []byte, encryptionKey []byte) (string, error) {
	size := len(data)
	size16 := size % 16
	size64 := size % 64

	switch {
	case size == 0:
		return "", nil
	case size16 == 0:
		ptext, err := lcrypt.Decrypt_aes256_ecb_plain(data, encryptionKey)
		if err != nil {
			return "", errors.Wrap(err, "failed to decrypt field")
		}
		return string(ptext), nil
	case size64 == 0 || size64 == 24 || size64 == 44:
		ptext, err := lcrypt.Decrypt_aes256_ecb_base64(data, encryptionKey)
		if err != nil {
			return "", errors.Wrap(err, "failed to decrypt field")
		}
		return string(ptext), nil
	case size16 == 1:
		ptext, err := lcrypt.Decrypt_aes256_cbc_plain(data[1:], encryptionKey)
		if err != nil {
			return "", errors.Wrap(err, "failed to decrypt field")
		}
		return string(ptext), nil
	case size64 == 6 || size64 == 26 || size64 == 50:
		ptext, err := lcrypt.Decrypt_aes256_cbc_base64(data, encryptionKey)
		if err != nil {
			return "", errors.Wrap(err, "failed to decrypt field")
		}
		return string(ptext), nil
	}
	return "", fmt.Errorf("Input doesn't seem to be AES-256 encrypted")
}

type stickyReader struct {
	err error
}

func (s *stickyReader) skipItem(reader io.Reader) {
	if s.hasErr() {
		return
	}

	skipItem(reader)
}
func (s *stickyReader) DecodeHex(val []byte) string {
	if s.hasErr() {
		return ""
	}
	ptext, err := lcrypt.DecodeHex(val)
	if err != nil {
		s.err = err
	}
	return string(ptext)
}
func (s *stickyReader) decryptAES256(name, encryptionKey []byte) string {
	if s.hasErr() {
		return ""
	}
	ptext, err := decryptAES256(name, encryptionKey)
	if err != nil {
		s.err = err
	}
	return ptext
}
func (s *stickyReader) readItem(reader io.Reader) []byte {
	if s.hasErr() {
		return nil
	}

	item, err := readItem(reader)
	if err != nil {
		s.err = err
	}

	return item
}
func (s stickyReader) hasErr() bool {
	return s.err != nil
}
