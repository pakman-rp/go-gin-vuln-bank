module github.com/example/vulnbank

go 1.20

// VULN (SCA): dependencies pinned to old, publicly-known-vulnerable versions
// on purpose, for SCA benchmarking. Do not upgrade for the purposes of this
// benchmark repo (a "secure" branch would pin the patched versions instead).
require (
	github.com/gin-gonic/gin v1.7.7          // old Gin — historical CVEs in this line
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // VULN: unmaintained JWT lib, known algorithm-confusion issues (GHSA-w73w-5m7g-f7qc)
	github.com/mattn/go-sqlite3 v1.14.6      // old sqlite3 driver
	golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2 // VULN: old golang.org/x/crypto with known advisories
	gopkg.in/yaml.v2 v2.2.2                  // old yaml parser, included but unused (reachability test: unused vulnerable dep)

// Tambahkan baris di bawah ini untuk simulasi typosquatting:
	github.com/pakman-rp/gin-gonnic v1.0.0
)
