package lastpass

import (
	"bytes"
	"fmt"
	"net/url"
	"encoding/xml"
	"strings"
	"io"
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
	accs := make([]*Account, len(accountChunks))

	for i, chunk := range accountChunks {
		account, err := parseAccount(bytes.NewReader(chunk), lp.sesh.key)
		if err != nil {
			return nil, err
		}
		accs[i] = account
	}
	return accs, nil
}

// GetAccount gets LastPass account by unique ID
// If not found, returns ErrAccountNotFound error
func (lp LastPass) GetAccount(id string) (*Account, error) {
	accs, err := lp.Search(id, Id, CaseInsensitive)
	if err != nil {
		return nil, err
	} else if accs == nil || len(accs) == 0 {
		return nil, ErrAccountNotFound
	}

	return accs[0], nil
}

// Search looks for LastPass accounts matching given args.
func (lp LastPass) Search(value string, field Field, method SearchMethod) ([]*Account, error) {
	accs, err := lp.GetAccounts()
	if err != nil {
		return nil, err
	}

	matchedAccounts := []*Account{}

	matchFunc := matchFuncs[method]
	for _, acc := range accs {
		if matchFunc(getValue(*acc, field), value) {
			matchedAccounts = append(matchedAccounts, acc)
		}
	}

	return matchedAccounts, nil
}

func (lp *LastPass) UpdateAccount(account *Account) (*Account, error) {

	_, err := lp.upsertAccount(account)
	return account, err
}

func (lp *LastPass) CreateAccount(account *Account) (*Account, error) {
	account.Id = "0"
	resp, err := lp.upsertAccount(account)
	if err != nil {
		return nil, err
	}

	// https://github.com/gnewton/chidley
	var response struct {
		Result struct {
			AttrAcctname1     string `xml:" acctname1,attr"  json:",omitempty"`
			AttrAcctname2     string `xml:" acctname2,attr"  json:",omitempty"`
			AttrAcctname3     string `xml:" acctname3,attr"  json:",omitempty"`
			AttrAcctname4     string `xml:" acctname4,attr"  json:",omitempty"`
			AttrAcctname5     string `xml:" acctname5,attr"  json:",omitempty"`
			AttrAcctname6     string `xml:" acctname6,attr"  json:",omitempty"`
			AttrAccts_version string `xml:" accts_version,attr"  json:",omitempty"`
			AttrAction        string `xml:" action,attr"  json:",omitempty"`
			AttrAid           string `xml:" aid,attr"  json:",omitempty"`
			AttrCaptcha_id    string `xml:" captcha_id,attr"  json:",omitempty"`
			AttrCount         string `xml:" count,attr"  json:",omitempty"`
			AttrCustom_js     string `xml:" custom_js,attr"  json:",omitempty"`
			AttrDeleted       string `xml:" deleted,attr"  json:",omitempty"`
			AttrEditlink      string `xml:" editlink,attr"  json:",omitempty"`
			AttrFav           string `xml:" fav,attr"  json:",omitempty"`
			AttrGrouping      string `xml:" grouping,attr"  json:",omitempty"`
			AttrLasttouch     string `xml:" lasttouch,attr"  json:",omitempty"`
			AttrLaunchjs      string `xml:" launchjs,attr"  json:",omitempty"`
			AttrLocalupdate   string `xml:" localupdate,attr"  json:",omitempty"`
			AttrMsg           string `xml:" msg,attr"  json:",omitempty"`
			AttrPwprotect     string `xml:" pwprotect,attr"  json:",omitempty"`
			AttrRemoteshare   string `xml:" remoteshare,attr"  json:",omitempty"`
			AttrSubmit_id     string `xml:" submit_id,attr"  json:",omitempty"`
			AttrUrid          string `xml:" urid,attr"  json:",omitempty"`
			AttrUrl           string `xml:" url,attr"  json:",omitempty"`
			AttrUsername      string `xml:" username,attr"  json:",omitempty"`
		} `xml:" result,omitempty" json:"result,omitempty"`
	}

	if err = xml.NewDecoder(strings.NewReader(resp)).Decode(&response); err != nil && err != io.EOF {
		return nil, err
	}

	account.Id = response.Result.AttrAid
	return account, nil
}

func (lp *LastPass) upsertAccount(account *Account) (string, error) {
	bUrl := BuildLastPassBaseURL("show_website.php")
	return post(bUrl, lp.sesh, account.encrypt(lp.sesh.key))
}

func (lp *LastPass) DeleteAccount(account *Account) error {
	bUrl := BuildLastPassBaseURL("show_website.php")
	values := &url.Values{
		"extjs":  []string{"1"},
		"token":  []string{"lp.sesh.token"},
		"delete": []string{"1"},
		"aid":    []string{account.Id},
	}

	resp, err := post(bUrl, lp.sesh, values)
	if err != nil {
		return err
	}

	resp = resp // TODO check output
	return nil
}
