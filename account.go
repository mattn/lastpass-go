package lastpass

import (
	"fmt"
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

func (a Account) encrypt(key []byte) *url.Values {
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
	vals.Set("username", b2s(lcrypt.Encrypt_aes256_cbc_base64(s2b(a.Username), key)))
	vals.Set("password", b2s(lcrypt.Encrypt_aes256_cbc_base64(s2b(a.Password), key)))
	vals.Set("extra", b2s(lcrypt.Encrypt_aes256_cbc_base64(s2b(a.Notes), key))) // notes
	vals.Set("name", b2s(lcrypt.Encrypt_aes256_cbc_base64(s2b(a.Name), key)))
	vals.Set("grouping", b2s(lcrypt.Encrypt_aes256_cbc_base64(s2b(a.Group), key)))
	vals.Set("pwprotect", "off") // TODO(while-loop) find out what this field does

	// request info
	vals.Set("extjs", "1")
	vals.Set("method", "cli")
	return vals
}

func s2b(string string) []byte {
	return []byte(string)
}

func b2s(data []byte) string {
	return string(data)
}
