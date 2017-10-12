package lastpass

import (
	"fmt"
	"github.com/pkg/errors"
	lcrypt "github.com/while-loop/lastpass-go/internal/crypt"
	"net/url"
)

type Account struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	Url      string `json:"url"`
	Group    string `json:"group"`
	Notes    string `json:"notes"`
}

func (a Account) String() string {
	return fmt.Sprintf("Id: %s, Name: %s, Username: %s", a.Id, a.Name, a.Username)
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

	vals.Set("aid", a.Id)
	vals.Set("url", b2s(lcrypt.EncodeHex(s2b(a.Url))))
	tmp, err := lcrypt.Encrypt_aes256_cbc_base64(s2b(a.Username), key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt username")
	}
	vals.Set("username", b2s(tmp))

	tmp, err = lcrypt.Encrypt_aes256_cbc_base64(s2b(a.Password), key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt Password")
	}
	vals.Set("password", b2s(tmp))

	tmp, err = lcrypt.Encrypt_aes256_cbc_base64(s2b(a.Notes), key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt Notes")
	}
	vals.Set("extra", b2s(tmp)) // notes

	tmp, err = lcrypt.Encrypt_aes256_cbc_base64(s2b(a.Name), key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encrypt Name")
	}
	vals.Set("name", b2s(tmp))

	tmp, err = lcrypt.Encrypt_aes256_cbc_base64(s2b(a.Group), key)
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
