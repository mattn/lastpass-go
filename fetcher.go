package lastpass

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	lcrypt "github.com/while-loop/lastpass-go/internal/crypt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"github.com/pkg/errors"
	"bytes"
)

type blob struct {
	bytes             []byte
	keyIterationCount int
}

type session struct {
	id                string
	token             string
	keyIterationCount int
	cookieJar         http.CookieJar
	key               []byte
}

const (
	loginPage = "login.php"
	iterationsPage = "iterations.php"
	getAccountsPage = "getaccts.php"

)

var (
	ErrInvalidPassword       = fmt.Errorf("invalid password")
	ErrInvalidEmail          = fmt.Errorf("invalid username or password")
	ErrInvalidGoogleAuthCode = fmt.Errorf("googleauthfailed")
	ErrInvalidYubiKey        = fmt.Errorf("yubikeyrestricted")
)

func login(username, password string, multiFactor string) (*session, error) {
	iterationCount, err := requestIterationCount(username)
	if err != nil {
		return nil, err
	}
	return make_session(username, password, iterationCount, multiFactor)
}

func make_session(username, password string, iterationCount int, multiFactor string) (*session, error) {
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := newClient(cookieJar)

	vals := url.Values{
		"method":     []string{"mobile"},
		"web":        []string{"1"},
		"xml":        []string{"1"},
		"username":   []string{username},
		"hash":       []string{string(makeHash(username, password, iterationCount))},
		"iterations": []string{fmt.Sprint(iterationCount)},
	}
	if multiFactor != "" {
		vals.Set("otp", multiFactor)
	}

	res, err := client.PostForm(buildLastPassURL(loginPage).String(), vals)
	if err != nil {
		return nil, errors.Wrap(err, "unable to reach LastPass servers")
	}

	defer res.Body.Close()
	var response struct {
		SessionId string `xml:"sessionid,attr"`
		Token     string `xml:"token,attr"`
		ErrResp *struct {
			AttrAllowmultifactortrust string `xml:" allowmultifactortrust,attr"  json:",omitempty"`
			AttrCause                 string `xml:" cause,attr"  json:",omitempty"`
			AttrHidedisable           string `xml:" hidedisable,attr"  json:",omitempty"`
			AttrMessage               string `xml:" message,attr"  json:",omitempty"`
			AttrTempuid               string `xml:" tempuid,attr"  json:",omitempty"`
			AttrTrustexpired          string `xml:" trustexpired,attr"  json:",omitempty"`
			AttrTrustlabel            string `xml:" trustlabel,attr"  json:",omitempty"`
		} `xml:" error,omitempty" json:"error,omitempty"`
	}

	// read to bytes for debugging
	b, err := ioutil.ReadAll(res.Body)
	if err != nil && err != io.EOF {
		return nil, err
	}

	err = xml.NewDecoder(bytes.NewReader(b)).Decode(&response)
	if err != nil {
		return nil, err
	}

	if response.ErrResp != nil {
		switch response.ErrResp.AttrCause {
		case "googleauthfailed", "googleauthrequired":
			return nil, ErrInvalidGoogleAuthCode
		case "unknownpassword":
			return nil, ErrInvalidPassword
		case "yubikeyrestricted":
			return nil, ErrInvalidYubiKey
		case "unknownemail":
			return nil, ErrInvalidEmail
		default:
			return nil, fmt.Errorf("%s", response.ErrResp.AttrMessage)
		}
	}

	key := makeKey(username, password, iterationCount)
	return &session{response.SessionId,
		response.Token,
		iterationCount,
		cookieJar,
		key,
	}, nil
}

func fetch(s *session) (*blob, error) {
	u := buildLastPassURL(getAccountsPage)
	u.RawQuery = (&url.Values{
		"mobile":    []string{"1"},
		"b64":       []string{"1"},
		"hash":      []string{"0.0"},
		"PHPSESSID": []string{s.id},
	}).Encode()

	client := newClient(s.cookieJar)

	res, err := client.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	b, err := ioutil.ReadAll(res.Body)
	if err != nil && err != io.EOF {
		return nil, err
	}

	//fmt.Println(string(b))
	if res.StatusCode == http.StatusForbidden {
		return nil, ErrInvalidPassword
	}

	b, err = base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return nil, err
	}
	return &blob{b, s.keyIterationCount}, nil
}

func post(postUrl *url.URL, s *session, values *url.Values) (string, error) {
	if values == nil {
		values = &url.Values{}
	}

	values.Set("token", string(s.token))
	client := newClient(s.cookieJar)

	res, err := client.PostForm(postUrl.String(), *values)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	b, err := ioutil.ReadAll(res.Body)
	if err != nil && err != io.EOF {
		return "", err
	}

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", res.Status)
	}

	return string(b), nil
}

func requestIterationCount(username string) (int, error) {
	res, err := http.DefaultClient.PostForm(
		buildLastPassURL(iterationsPage).String(),
		url.Values{
			"email": []string{username},
		})
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return 0, err
	}
	count, err := strconv.Atoi(string(b))
	if err != nil {
		return 0, err
	}
	return count, nil
}

func makeKey(username, password string, iterationCount int) []byte {
	if iterationCount == 1 {
		b := sha256.Sum256([]byte(username + password))
		return b[:]
	}
	return pbkdf2.Key([]byte(password), []byte(username), iterationCount, 32, sha256.New)
}

func makeHash(username, password string, iterationCount int) []byte {
	key := makeKey(username, password, iterationCount)
	if iterationCount == 1 {
		b := sha256.Sum256([]byte(string(lcrypt.EncodeHex(key)) + password))
		return lcrypt.EncodeHex(b[:])
	}
	return lcrypt.EncodeHex(pbkdf2.Key([]byte(key), []byte(password), 1, 32, sha256.New))
}

// used to mock lastpass responses
var newClient = func(jar http.CookieJar) *http.Client {
	return &http.Client{
		Jar: jar,
	}
}

func buildLastPassURL(path string) *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   "lastpass.com",
		Path:   path,
	}
}