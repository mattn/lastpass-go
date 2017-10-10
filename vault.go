package lastpass

import (
	"bytes"
)

type Vault struct {
	Accounts []*Account `json:"accounts"`
}

func CreateVault(username, password string) (*Vault, error) {
	session, err := login(username, password)
	if err != nil {
		return nil, err
	}
	blob, err := fetch(session)
	if err != nil {
		return nil, err
	}
	chunks, err := extractChunks(bytes.NewReader(blob.bytes), []uint32{chunkIdFromString("ACCT")})
	if err != nil {
		return nil, err
	}
	accountChunks := chunks[chunkIdFromString("ACCT")]
	vault := &Vault{Accounts: make([]*Account, len(accountChunks))}

	encryptionKey := makeKey(username, password, blob.keyIterationCount)

	for i, chunk := range accountChunks {
		account, err := parseAccount(bytes.NewReader(chunk), encryptionKey)
		if err != nil {
			return nil, err
		}
		vault.Accounts[i] = account
	}
	return vault, nil
}
