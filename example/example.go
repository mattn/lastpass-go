package main

import (
	"encoding/json"
	"fmt"
	"github.com/while-loop/lastpass-go"
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

	lp, err := lastpass.New(username, password)
	if err != nil {
		log.Fatal(err)
	}

	accs, err := lp.GetAccounts()
	if err != nil {
		log.Fatal(err)
	}

	for _, account := range accs {
		json.NewEncoder(os.Stdout).Encode(account)
		fmt.Println()
	}
}
