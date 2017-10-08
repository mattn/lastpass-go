package lastpass

import (
	"bytes"
	"fmt"
)

var (
	ErrAccountNotFound = fmt.Errorf("account not found")
)

type LastPass struct {
	sesh  *session
	email string
}

func New(email, password string) (*LastPass, error) {
	session, err := login(email, password)
	if err != nil {
		return nil, err
	}

	// try to "actually" login because login does
	// not check for valid username/password combos
	_, err = fetch(session)
	if err != nil {
		return nil, err
	}

	return &LastPass{sesh: session, email: email}, nil
}

func (lp LastPass) Email() string {
	return lp.email
}

func (lp LastPass) GetAccounts() ([]*Account, error) {
	blob, err := fetch(lp.sesh)
	if err != nil {
		return nil, err
	}

	chunks, err := extractChunks(bytes.NewReader(blob.bytes), []uint32{chunkIdFromString("ACCT")})
	if err != nil {
		return nil, err
	}
	accountChunks := chunks[chunkIdFromString("ACCT")]
	vault := &Vault{Accounts: make([]*Account, len(accountChunks))}

	for i, chunk := range accountChunks {
		account, err := parseAccount(bytes.NewReader(chunk), lp.sesh.key)
		if err != nil {
			return nil, err
		}
		vault.Accounts[i] = account
	}
	return vault.Accounts, nil
}

// GetAccount gets LastPass account by unique ID
// If not found, returns ErrAccountNotFound error
func (lp LastPass) GetAccount(id string) (*Account, error) {
	return lp.Search(id, ID, CASEINSENSITVE)
}

// Search looks for LastPass accounts matching given args.
// Returns the first account found or ErrAccountNotFound error
func (lp LastPass) Search(value string, field Field, method SearchMethod) (*Account, error) {
	accs, err := lp.GetAccounts()
	if err != nil {
		return nil, err
	}

	err = ErrAccountNotFound
	var account *Account

	matchFunc := matchFuncs[method]
	for _, acc := range accs {
		if matchFunc(getValue(*acc, field), value) {
			account = acc
			err = nil
			break
		}
	}

	return account, err
}

func (lp *LastPass) UpdateAccount(account Account) (*Account, error) {
	return nil, fmt.Errorf("NotImplemented")
}

func (lp *LastPass) CreateAccount(account Account) error {
	return fmt.Errorf("NotImplemented")
}

func (lp *LastPass) Delete(account Account) error {
	return fmt.Errorf("NotImplemented")
}
