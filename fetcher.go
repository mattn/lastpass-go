package lastpass

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	lcrypt "github.com/while-loop/lastpass-go/internal/crypt"
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

func BuildLastPassBaseURL(path string) *url.URL {
	return &url.URL{
		Scheme: "https",
		Host:   "lastpass.com",
		Path:   path,
	}
}

var (
	ErrInvalidPassword = fmt.Errorf("invalid username or password")
)

func login(username, password string) (*session, error) {
	iterationCount, err := requestIterationCount(username)
	if err != nil {
		return nil, err
	}
	return make_session(username, password, iterationCount)
}

func make_session(username, password string, iterationCount int) (*session, error) {
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Jar: cookieJar,
	}
	res, err := client.PostForm(
		BuildLastPassBaseURL("login.php").String(),
		url.Values{
			"method":     []string{"mobile"},
			"web":        []string{"1"},
			"xml":        []string{"1"},
			"username":   []string{username},
			"hash":       []string{string(makeHash(username, password, iterationCount))},
			"iterations": []string{fmt.Sprint(iterationCount)},
		})
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var response struct {
		SessionId string `xml:"sessionid,attr"`
		Token     string `xml:"token,attr"`
	}
	err = xml.NewDecoder(res.Body).Decode(&response)
	if err != nil {
		return nil, err
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
	u := BuildLastPassBaseURL("getaccts.php")
	u.RawQuery = (&url.Values{
		"mobile":    []string{"1"},
		"b64":       []string{"1"},
		"hash":      []string{"0.0"},
		"PHPSESSID": []string{s.id},
	}).Encode()
	client := &http.Client{
		Jar: s.cookieJar,
	}
	res, err := client.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusForbidden {
		return nil, ErrInvalidPassword
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil && err != io.EOF {
		return nil, err
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
	// TODO fix encoding b64
	// 2017/10/09 11:46:30 <xmlresponse><result action="added" aid="2215972459054203220" urid="0" msg="accountadded" acctname1="" acctname2="" acctname3="" acctname4="" acctname5="" acctname6="" grouping="!dBYwP0uxf3HfGMqnRoWcMQ==|SWtDmymO8K7rB8wJWAUVoQ==" count="0" lasttouch="0000-00-00 00:00:00" editlink="" url="687474703a2f2f66616365626f6f6b2e636f6d" fav="0" launchjs="" deleted="0" remoteshare="0" username="IbMaWDJ4UpzVaOACQYsaVZ8B3U4TsvwBmwUKg1Ok0Q6eAAAAAAAAAA==" localupdate="1" accts_version="36" pwprotect="0" submit_id="" captcha_id="" custom_js="" ></result></xmlresponse>
	client := &http.Client{
		Jar: s.cookieJar,
	}

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

func encodeValues(values *url.Values) *url.Values {
	newValues := &url.Values{}
	for key, val := range *values {
		for _, v := range val {
			newValues.Add(key, base64.StdEncoding.EncodeToString(s2b(v)))
		}
	}
	return newValues
}

func requestIterationCount(username string) (int, error) {
	res, err := http.DefaultClient.PostForm(
		BuildLastPassBaseURL("iterations.php").String(),
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
