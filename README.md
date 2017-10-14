LastPass Go API
===============

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

Check out [lastpass/lastpass-cli](https://github.com/LastPass/lastpass-cli) for an Official LastPass product

This is a port of the [Ruby LastPass API](https://github.com/detunized/lastpass-ruby).

Features
--------

- Create/Update accounts
- Delete accounts
- Get accounts
- Multi-factor authentication

Installation
------------

```
$ go get github.com/while-loop/lastpass-go
```

Usage
-----

[Example Usages](vault_test.go)

```go
lp, _ := lastpass.New(email, password)
accs, _ := lp.GetAccounts()
for _, account := range accs {
	fmt.Println(account.Username, account.Password)
}
```

#### With Multi-factor Auth

```go
lp, err := New(email, password, WithMultiFactor("5412548"))
accs, _ := lp.GetAccounts()
for _, account := range accs {
	fmt.Println(account.Username, account.Password)
}
```

TODO
----

These are future plans for the project, feel free fork/pr these features
if I don't get to them in time.

- Shared groups
- Secured notes

Changelog
---------

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

[CHANGELOG.md](CHANGELOG.md)

License
-------

lastpass-go is licensed under the MIT license. See [LICENSE](LICENSE) for details.

Note that this repository includes code of `ecb` (Electronic Code Block) provided by Go Authors.

Original Author
---------------

Yasuhiro Matsumoto (a.k.a [mattn](https://github.com/mattn))

Current Author
--------------

Anthony Alves
