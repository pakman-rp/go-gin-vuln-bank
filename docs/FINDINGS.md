# Expected Findings — VulnBank (Go + Gin)

This document lists the intentional vulnerabilities seeded in this repository,
for scoring SAST/SCA/secret-scanning tool coverage during POC.

## SAST — Expected Findings

| # | Location | Vulnerability | CWE | OWASP Top 10 (2021) | ASVS | Severity |
|---|----------|---------------|-----|----------------------|------|----------|
| 1 | `models/user.go:FindByCredentials` | SQL Injection | CWE-89 | A03: Injection | V5.3.4 | Critical |
| 2 | `models/user.go:PromoteToAdmin` | SQL Injection | CWE-89 | A03: Injection | V5.3.4 | Critical |
| 3 | `models/transaction.go:Search` | SQL Injection | CWE-89 | A03: Injection | V5.3.4 | Critical |
| 4 | `controllers/search_controller.go` | Reflected XSS (html format) | CWE-79 | A03: Injection | V5.3.3 | High |
| 5 | `middleware/auth.go` | Improper JWT signature verification | CWE-347 | A07: Ident./Auth Failures | V3.5 | Critical |
| 6 | `db/db.go`, `middleware/auth.go`, `controllers/auth_controller.go` | Hardcoded credentials/secrets | CWE-798 | A07 | V2.10 | Critical |
| 7 | `controllers/admin_controller.go:ListAllUsers` | Missing authorization (role not checked) | CWE-862 | A01: Broken Access Control | V4.1 | High |
| 8 | `controllers/admin_controller.go:PromoteToAdmin` | Privilege escalation | CWE-269 | A01 | V4.1 | Critical |
| 9 | `controllers/user_controller.go:GetUser/GetStatement` | IDOR | CWE-639 | A01 | V4.2 | High |
| 10 | `controllers/user_controller.go:OpenRedirect` | Open Redirect | CWE-601 | A01 | V5.1 | Medium |
| 11 | `controllers/upload_controller.go` | Unrestricted file upload / path traversal | CWE-434, CWE-22 | A05: Security Misconfiguration | V12.1, V12.4 | Critical |
| 12 | `controllers/auth_controller.go:Register` | MD5 for password hashing | CWE-327, CWE-916 | A02: Cryptographic Failures | V2.4 | High |
| 13 | `controllers/auth_controller.go:Register` | Weak PRNG (`math/rand`) for salt | CWE-338 | A02 | V6.3 | Medium |
| 14 | `db/db.go` seed | Plaintext password storage | CWE-256 | A02 | V2.4 | Critical |
| 15 | `controllers/auth_controller.go` / `middleware/auth.go` | Sensitive data (password, JWT) in logs | CWE-532 | A09: Logging Failures | V7.1 | Medium |
| 16 | `controllers/auth_controller.go:Login` | Insecure cookie (no Secure/HttpOnly/SameSite) | CWE-614, CWE-1004 | A05 | V3.4 | Medium |
| 17 | `main.go` | Wildcard CORS with credentials | CWE-942 | A05 | V14.5 | High |
| 18 | `main.go` | Missing security headers (CSP, X-Frame-Options, HSTS) | CWE-693 | A05 | V14.4 | Low/Medium |
| 19 | `main.go`, `Dockerfile` | Debug mode enabled by default | CWE-489 | A05 | V14.3 | Medium |
| 20 | `controllers/admin_controller.go:DebugEnv` | Sensitive info exposure (env dump) | CWE-215, CWE-497 | A05 | V8.3 | High |
| 21 | `main.go` (`/files` static route) | Unauthenticated directory listing of uploads | CWE-548 | A01 | V12.3 | Medium |
| 22 | `controllers/auth_controller.go:Register` | Missing password policy | CWE-521 | A07 | V2.1 | Medium |

## SCA — Expected Findings

| Package | Version pinned | Known issue class | Reachability |
|---------|----------------|--------------------|---------------|
| `github.com/gin-gonic/gin` | v1.7.7 | Historical CVEs in Gin 1.7.x line | Reachable (core framework) |
| `github.com/dgrijalva/jwt-go` | v3.2.0+incompatible | Unmaintained; algorithm-confusion advisory | Reachable (`middleware/auth.go`) |
| `github.com/mattn/go-sqlite3` | v1.14.6 | Older CGO sqlite driver | Reachable |
| `golang.org/x/crypto` | pinned old pseudo-version | Multiple historical advisories | Indirect / transitive |
| `gopkg.in/yaml.v2` | v2.2.2 | Included, **not imported anywhere in source** | **Unused vulnerable dependency** (reachability = none) — use to test that SCA tool correctly deprioritizes/flags as non-reachable |

### Typosquatting / malware-name test set (documentation only — do not install)
The following are **fictional package names** for testing SCA malicious-package
detection rules. They are not referenced in `go.mod` and most will not resolve:
`ginn`, `gin-gonicc`, `jwt-goo`, `sqlite33`. See `docs/TYPOSQUAT_NOTES.md`.

## Secret Detection — Expected Findings
All secrets below live in `.env.example` and are duplicated inline in
`middleware/auth.go` / `controllers/auth_controller.go` for source-code
secret-scanning coverage. **All values are fake.**

- AWS Access Key + Secret
- Azure Client Secret
- GCP API Key
- GitHub PAT / GitLab Token
- Stripe Secret Key / Slack Token / OpenAI API Key / Twilio Auth Token
- OAuth Client Secret / generic Bearer Token
- Fake RSA private key block
- Fake SSH private key block
- Hardcoded JWT secret (`SuperSecretJWT`) — appears in `.env.example`,
  `middleware/auth.go`, and `controllers/auth_controller.go`
- Hardcoded DB password (`Password123`)
- Hardcoded admin credentials (`admin` / `admin123`) in `db/db.go`

## Cryptography Rule Test Coverage
- MD5: `controllers/auth_controller.go` (`crypto/md5`)
- Weak PRNG: `controllers/auth_controller.go` (`math/rand`, unseeded-pattern misuse)
- Hardcoded key: `middleware/auth.go`, `controllers/auth_controller.go`

## SBOM Notes
- CycloneDX/SPDX generation not wired into this seed version; recommended
  tool: `cyclonedx-gomod` or vendor SBOM step in CI (see `.github/workflows/ci.yml`
  `sca-scan` job placeholder).
- Expect the SBOM to list all 5 direct dependencies in `go.mod` plus their
  transitive graph (notably `golang.org/x/crypto` as indirect/transitive).

## License Detection
| Dependency | License |
|---|---|
| gin-gonic/gin | MIT |
| dgrijalva/jwt-go | MIT |
| mattn/go-sqlite3 | MIT |
| golang.org/x/crypto | BSD-3-Clause |
| gopkg.in/yaml.v2 | Apache-2.0 (dual MIT/Apache-2.0 in v2 line) |

This set intentionally mixes MIT / BSD / Apache-licensed dependencies so
license-policy engines have real license diversity to classify (no
GPL/AGPL example is reachable via Go modules here; add a `CGO`-linked GPL
library in the expanded version if copyleft-detection testing is required).
