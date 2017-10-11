package crypt

import (
	"testing"
	"bytes"
	"github.com/stretchr/testify/assert"
)

func TestIntBase64Encode(t *testing.T) {
	data := []byte("1231231231231231")
	iv := []byte("3213213213213213")
	b := bytes.NewBuffer([]byte("!"))
	b.Write(iv)
	b.Write(data)

	ac := bytes.NewBufferString("!")
	ac.Write(Base64Encode(iv))
	ac.WriteString("|")
	ac.Write(Base64Encode(data))

	assert.Equal(t, ac.Bytes(), intBase64Encode(b.Bytes()))
}

func TestIntBase64EncodeLonger(t *testing.T) {
	data := []byte("kjnsdfvkljnsdfkjdfkjnvsdfkjnvsdkfjnvslkdjfnklvjsdnfkvljsndfvdkjf")
	iv := []byte("3213213213213213")
	b := bytes.NewBuffer([]byte("!"))
	b.Write(iv)
	b.Write(data)

	ac := bytes.NewBufferString("!")
	ac.Write(Base64Encode(iv))
	ac.WriteString("|")
	ac.Write(Base64Encode(data))

	assert.Equal(t, ac.Bytes(), intBase64Encode(b.Bytes()))
}

func TestIntBase64EncodeNoCustomizing(t *testing.T) {
	data := []byte("r23p4jsdaskjldfnaslkmdjfmnasdfsdjnfalksdjfnmlaksjdnfmaksnjdfmmr")
	iv := []byte("3213213213213213")
	b := bytes.NewBuffer([]byte("!"))
	b.Write(iv)
	b.Write(data)


	actual := Base64Encode(b.Bytes())
	assert.Equal(t, actual, intBase64Encode(b.Bytes()))
}
