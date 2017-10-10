package lastpass

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestBackwardsCompatLogin(t *testing.T) {
	vault, err := CreateVault(config.email, config.password)
	assert.NoError(t, err)
	assert.NotNil(t, vault)
}

func TestBackwardsCompatErr(t *testing.T) {
	vault, err := CreateVault("fakkeemail", "fakepassword")
	assert.Equal(t, ErrInvalidPassword, err)
	assert.Nil(t, vault)
}
