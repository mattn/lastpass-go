package main

import (
	"encoding/json"
	"fmt"
	"github.com/mattn/go-lastpass"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func main() {
	b, err := ioutil.ReadFile("example/credentials.txt")
	if err != nil {
		log.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	username := lines[0]
	password := lines[1]

	vault, err := lastpass.CreateVault(username, password)
	if err != nil {
		log.Fatal(err)
	}

	for _, account := range vault.Accounts {
		json.NewEncoder(os.Stdout).Encode(account)
		fmt.Println()
	}
}
