# VulnBank — Go + Gin Intentionally Vulnerable Benchmark App

> ⚠️ **DO NOT DEPLOY. DO NOT USE IN PRODUCTION.**
> This repository is an intentionally vulnerable benchmark application, built in the
> style of OWASP Benchmark / WebGoat / Juice Shop, for evaluating **SAST/SCA/Secret
> Scanning tools** (SonarQube, Checkmarx, Veracode, Semgrep, Snyk, GitHub Advanced
> Security, Mend, Black Duck, etc.) during Proof-of-Concept (POC) exercises.
>
> Every secret in this repo is **fake**. Every vulnerability is **intentional** and
> commented with `// VULN:` and its CWE ID. Do not copy this code into real projects.

## Business Scenario
A small fictional retail bank ("VulnBank") with account management, an admin
console, file upload for KYC documents, and a transaction search API.

## Stack
- Go 1.20, Gin web framework
- SQLite (via intentionally old `go-sqlite3` driver pinned in `go.mod`)
- JWT auth (deliberately weak validation — see `docs/FINDINGS.md`)

## Running

```bash
cp .env.example .env
docker compose up --build
```

App will be available at `http://localhost:8080`.

## Default (Intentionally Hardcoded) Accounts
| username | password   | role  |
|----------|------------|-------|
| admin    | admin123   | admin |
| jdoe     | Password1  | user  |

See `docs/FINDINGS.md` for the full expected SAST/SCA/Secret-detection findings,
CWE/OWASP mapping, and SBOM notes.

## Repository Layout
```
controllers/   HTTP handlers (auth, admin, upload, search, transfer)
models/        Data models + raw-SQL data access (SQL injection lives here)
middleware/    Auth middleware (weak JWT validation)
db/            DB bootstrap + seed data
uploads/       Runtime upload target (unrestricted file upload)
docs/          Expected findings, CWE/OWASP mapping, SBOM notes
.github/workflows/  CI pipeline incl. SAST/SCA/secret-scan stage stubs
Jenkinsfile    Jenkins pipeline stub with fail-on-severity gate
```

## Not Included Yet
This is the seed version of the repo. Planned expansion (on request): full
CRUD for accounts, cron/background job, XXE endpoint, SSRF endpoint,
CycloneDX/SPDX SBOM generation scripts, GitLab CI variant, typosquatting
branch for SCA malware-name testing.
