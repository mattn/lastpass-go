# LastPass Go API

<p align="center">
  <img src="https://github.com/while-loop/lastpass-go/blob/master/resources/keys.png">
  <br><br><br>
  <a href="https://godoc.org/github.com/while-loop/lastpass-go"><img src="https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square"></a>
  <a href="https://travis-ci.org/while-loop/lastpass-go"><img src="https://img.shields.io/travis/while-loop/lastpass-go.svg?style=flat-square"></a>
  <a href="https://github.com/while-loop/lastpass-go/releases"><img src="https://img.shields.io/github/release/while-loop/lastpass-go.svg?style=flat-square"></a>
  <a href="https://coveralls.io/github/while-loop/lastpass-go"><img src="https://img.shields.io/coveralls/while-loop/lastpass-go.svg?style=flat-square"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/mashape/apistatus.svg?style=flat-square"></a>
</p>


**This is an unofficial LastPass API.**

This is a port of [Ruby API](https://github.com/detunized/lastpass-ruby).

## Installation

```
$ go get github.com/while-loop/lastpass-go
```

## Usage

```go
lp, _ := lastpass.New(username, password)
accs, _ := lp.GetAccounts()
for _, account := range accs {
	fmt.Println(account.Username, account.Password)
}
```

Changelog
---------

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

[CHANGELOG.md](CHANGELOG.md)

## License

lastpass-go is licensed under the MIT license. See [LICENSE](LICENSE) for details.

Note that this repository includes code of `ecb` (Electronic Code Block) provided by Go Authors.

## Original Author

Yasuhiro Matsumoto (a.k.a [mattn](https://github.com/mattn))

## Current Author

Anthony Alves
