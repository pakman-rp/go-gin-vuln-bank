# Typosquatting / Malicious-Package Detection Test Notes

These package names are **fictional** and are NOT added to `go.mod`. They are
documented here only so a QA engineer can manually add one to a scratch branch
to verify an SCA tool's typosquat/malware-name heuristics fire correctly. Do
not attempt to `go get` these against the real module proxy in a shared
environment — they may not resolve, and some fuzzy names occasionally do
resolve to unrelated third-party code that has not been vetted.

| Fictional name | Mimics |
|---|---|
| `ginn` | `gin-gonic/gin` |
| `gin-gonicc` | `gin-gonic/gin` |
| `jwt-goo` | `dgrijalva/jwt-go` |
| `sqlite33` | `mattn/go-sqlite3` |

Recommended usage: add one line to a throwaway `go.mod` in an isolated,
network-restricted sandbox, run the SCA tool's dependency-confusion /
typosquat detector, and confirm it flags the entry, then discard the branch.
