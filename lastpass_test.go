package lastpass

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestInvalidEmail(t *testing.T) {
	lp, err := New("fakeemail@hotmail.com", "fakepassword")
	assert.Nil(t, lp)
	assert.Equal(t, ErrInvalidPassword, err)
}

func TestCRUD(t *testing.T) {
	t.Skip("LassPass.CreateAccount not fully impl")

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

	assert.Equal(t, 3, len(accs))

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
		assert.NotNil(t, lp.DeleteAccount(act))
	}

	assert.NoError(t, err)
	assert.Empty(t, actuals)
}

func mustDeleteAccounts(lp *LastPass) {
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
