package lastpass

import (
	"fmt"
	"net/url"

	lcrypt "github.com/djui/lastpass-go/internal/crypt"
	"github.com/pkg/errors"
)

// Account describes an account.
type Account struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Group    string `json:"group"`
	Notes    string `json:"notes"`
}

func (a Account) String() string {
	return fmt.Sprintf("Id: %s, Name: %s, Username: %s", a.ID, a.Name, a.Username)
}

func (a Account) encrypt(key []byte) (*url.Values, error) {
	//Id       plain
	//Name     aes & b64
	//Username aes & b64
	//Password aes & b64
	//Url      hex
	//Group    aes & b64
	//Notes    aes & b64

	vals := &url.Values{}

	vals.Set("aid", a.ID)
	vals.Set("url", b2s(lcrypt.EncodeHex(s2b(a.URL))))
	tmp, err := lcrypt.EncryptAES256CBCBase64(s2b(a.Username), key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt username")
	}
	vals.Set("username", b2s(tmp))

	tmp, err = lcrypt.EncryptAES256CBCBase64(s2b(a.Password), key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt Password")
	}
	vals.Set("password", b2s(tmp))

	tmp, err = lcrypt.EncryptAES256CBCBase64(s2b(a.Notes), key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt Notes")
	}
	vals.Set("extra", b2s(tmp)) // notes

	tmp, err = lcrypt.EncryptAES256CBCBase64(s2b(a.Name), key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt Name")
	}
	vals.Set("name", b2s(tmp))

	tmp, err = lcrypt.EncryptAES256CBCBase64(s2b(a.Group), key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt Group")
	}
	vals.Set("grouping", b2s(tmp))

	vals.Set("pwprotect", "off")
	// request info
	vals.Set("extjs", "1")
	vals.Set("method", "cli")
	return vals, nil
}

func s2b(string string) []byte {
	return []byte(string)
}

func b2s(data []byte) string {
	return string(data)
}
