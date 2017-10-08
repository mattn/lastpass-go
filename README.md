# LastPass Go API

**This is unofficial LastPass API.**

This is a port of [Ruby API](https://github.com/detunized/lastpass-ruby).

## Usage

```go
lp, _ := lastpass.New(username, password)
accs, _ := lp.GetAccounts()
for _, account := range accs {
	fmt.Println(account.Username, account.Password)
}
```

## Requirements

golang

## Installation

```
$ go get github.com/while-loop/lastpass-go
```

## License

MIT

Note that this repository include code of `ecb` (Electronic Code Block) provided by Go Authors.

## Author

Yasuhiro Matsumoto (a.k.a [mattn](https://github.com/mattn))
