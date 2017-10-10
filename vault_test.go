package lastpass

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestBackwardsCompatLogin(t *testing.T) {
	vaultLogin(t)
}

func TestBackwardsCompatVault(t *testing.T) {
	vault := vaultLogin(t)

	assert.NotNil(t, vault.Accounts)
}

func TestBackwardsCompatErr(t *testing.T) {
	vault, err := CreateVault("fakkeemail", "fakepassword")
	assert.Equal(t, ErrInvalidPassword, err)
	assert.Nil(t, vault)
}


func vaultLogin(t *testing.T) *Vault{
	vault, err := CreateVault(config.email, config.password)
	assert.NoError(t, err)
	assert.NotNil(t, vault)
	return vault
}