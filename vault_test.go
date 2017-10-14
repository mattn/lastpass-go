package lastpass

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"gopkg.in/jarcoal/httpmock.v1"
)

const (
	GoLpEmail = "GO_LP_EMAIL"
	GoLpPass  = "GO_LP_PASS"
)

// DONT USE YOUR REAL LASTPASS ACCOUNT
// THESE TEST WILL WIPE YOUR DATA
//
// to include personal passwords,
// set env vars GO_LP_EMAIL &  GO_LP_PASS
//
// DONT USE YOUR REAL LASTPASS ACCOUNT
// THESE TEST WILL WIPE YOUR DATA
var config = struct {
	email    string
	password string
}{
	email:    os.Getenv(GoLpEmail),
	password: os.Getenv(GoLpPass),
}

func TestInvalidEmail(t *testing.T) {
	lp, err := New("fakeemail@hotmail.com", "fakepassword")
	assert.Nil(t, lp)
	assert.EqualError(t, err, ErrInvalidEmail.Error())
}

func TestInvalidPassword(t *testing.T) {
	lp, err := New(config.email, "fakepassword")
	assert.Nil(t, lp)
	assert.EqualError(t, err, ErrInvalidPassword.Error())
}

func TestCRUD(t *testing.T) {
	needsLogin(t)

	accs := map[string]*Account{
		"site1": {Name: "site1", Username: "site1@yahoo.com", Password: "site1", Url: "site1.com"},
		"site2": {Name: "site2", Username: "site2@yahoo.com", Password: "site2", Url: "site2.com"},
		"site3": {Name: "site3", Username: "site2@yahoo.com", Password: "site3", Url: "site2.com"},
	}

	lp, err := New(config.email, config.password)
	assert.NoError(t, err)
	assert.NotNil(t, lp)

	// start fresh
	mustDeleteAccounts(lp)

	for _, a := range accs {
		newa, err := lp.CreateAccount(a)
		assert.NoError(t, err)
		assert.NotNil(t, newa)
	}

	actuals, err := lp.GetAccounts()
	assert.NoError(t, err)
	assert.Equal(t, len(accs), len(actuals))

	for _, act := range actuals {
		acc, exists := accs[act.Name]
		assert.True(t, exists)
		assert.Equal(t, acc.Username, act.Username)
		assert.Nil(t, lp.DeleteAccount(act))
	}

	actuals, err = lp.GetAccounts()
	assert.NoError(t, err)
	assert.Empty(t, actuals)
}

func TestChangePassword(t *testing.T) {
	needsLogin(t)

	lp, err:=New(config.email, config.password)
	assert.NoError(t, err)
	assert.NotNil(t, lp)

	acc := &Account{Name: "testchange", Username: "site1@yahoo.com", Password: "site1", Url: "site1.com"}
	acc, err = lp.CreateAccount(acc)
	assert.NotEqual(t, "0", acc.Id)
	assert.NoError(t, err)

	acc.Password = "newpass"
	_, err = lp.UpdateAccount(acc)
	assert.NoError(t, err)

	a, err :=lp.GetAccount(acc.Id)
	assert.NoError(t, err)
	assert.Equal(t, "newpass", a.Password)

	assert.NoError(t, lp.DeleteAccountById(a.Id))
}

func TestIncorrectGoogleAuthCode(t *testing.T) {
	if os.Getenv("MOCK_LP") != "" {
		t.Logf("running %s in mock mode", t.Name())
		httpmock.Activate()
		defer httpmock.DeactivateAndReset()

		data := `<response><error message="Google Authenticator authentication failed!" cause="googleauthfailed" allowmultifactortrust="true" tempuid="160828192" trustexpired="0" trustlabel="" hidedisable="false"  /></response>`
		httpmock.RegisterResponder("POST", buildLastPassURL(iterationsPage).String(), httpmock.NewStringResponder(200, "5461"))
		httpmock.RegisterResponder("POST", buildLastPassURL(loginPage).String(), httpmock.NewStringResponder(200, data))
	}

	lp, err := New("zqg45101@loaoa.com", "qwerty123", WithMultiFactor("-3"))
	assert.Nil(t, lp)
	assert.EqualError(t, err, ErrInvalidGoogleAuthCode.Error())
}

func TestNoGoogleAuthCodeGiven(t *testing.T) {
	if os.Getenv("MOCK_LP") != "" {
		t.Logf("running %s in mock mode", t.Name())
		httpmock.Activate()
		defer httpmock.DeactivateAndReset()

		data := `<response><error message="Google Authenticator authentication required! Upgrade your browser extension so you can enter it." cause="googleauthrequired" allowmultifactortrust="true" tempuid="160828192" trustexpired="0" trustlabel="" hidedisable="false"  /></response>`
		httpmock.RegisterResponder("POST", buildLastPassURL(iterationsPage).String(), httpmock.NewStringResponder(200, "5461"))
		httpmock.RegisterResponder("POST", buildLastPassURL(loginPage).String(), httpmock.NewStringResponder(200, data))
	}

	lp, err := New("ocr94395@loaoa.com", "qwerty123")
	assert.Nil(t, lp)
	assert.EqualError(t, err, ErrInvalidGoogleAuthCode.Error())
}
func TestInvalidYubiKey(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	t.Logf("running %s in mock mode", t.Name())

	data := `<response><error message="blah blah" cause="yubikeyrestricted" allowmultifactortrust="true" tempuid="160828192" trustexpired="0" trustlabel="" hidedisable="false"  /></response>`
	httpmock.RegisterResponder("POST", buildLastPassURL(iterationsPage).String(), httpmock.NewStringResponder(200, "5461"))
	httpmock.RegisterResponder("POST", buildLastPassURL(loginPage).String(), httpmock.NewStringResponder(200, data))

	lp, err := New("zqg4s5101@loaoa.com", "qwerty123")
	assert.Nil(t, lp)
	assert.EqualError(t, err, ErrInvalidYubiKey.Error())
}

func mustDeleteAccounts(lp *Vault) {
	accs, err := lp.GetAccounts()
	if err != nil {
		panic(err)
	}

	for _, act := range accs {
		if err = lp.DeleteAccount(act); err != nil {
			panic(err)
		}
	}
}

func needsLogin(t *testing.T) {
	if config.email == "" || config.password == "" {
		t.Skipf("skipping test %s. Login requirement not met", t.Name())
	}
}
