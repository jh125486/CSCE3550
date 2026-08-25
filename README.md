# CSCE 3550 Gradebot Client

[![Go Version](https://img.shields.io/github/go-mod/go-version/jh125486/CSCE3550)](https://golang.org/)
[![test](https://github.com/jh125486/CSCE3550/actions/workflows/test.yaml/badge.svg)](https://github.com/jh125486/CSCE3550/actions/workflows/test.yaml)
[![Coverage Status](https://codecov.io/gh/jh125486/CSCE3550/branch/main/graph/badge.svg)](https://codecov.io/gh/jh125486/CSCE3550)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=jh125486_CSCE3550&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=jh125486_CSCE3550)
[![Release](https://img.shields.io/github/release/jh125486/CSCE3550.svg)](https://github.com/jh125486/CSCE3550/releases)

CLI grading client for CSCE 3550 (Foundations of Cybersecurity) assignments. Submits your project's server for automated grading against project1/2/3 rubrics.

## Projects

- **Project 1**: JWKS server — code quality, structure, and JWT/JWKS implementation security.
- **Project 2**: Adds SQLite-backed key storage — database query security and parameterization.
- **Project 3**: Adds authentication and rate limiting — auth correctness and rate-limit behavior.

## Installation

Download a prebuilt binary from the [Releases](https://github.com/jh125486/CSCE3550/releases) page, or build from source:

```bash
git clone https://github.com/jh125486/CSCE3550.git
cd CSCE3550
go build -o gradebot .
```

## Usage

Run your server, then point the client at it:

```bash
# Project 1
./gradebot project1 --port 8080

# Project 2
./gradebot project2 --port 8080 --code-dir . --database totally_not_my_privateKeys.db

# Project 3
./gradebot project3 --port 8080 --code-dir . --database totally_not_my_privateKeys.db
```

Run `./gradebot --help` or `./gradebot <project> --help` for the full flag list.

## ⚠️ `BUILD_ID`

`BUILD_ID` is a maintainer-only secret baked into release binaries by CI (`.github/workflows/deploy.yaml`) — it is **not** something students set, pass as a flag, or put in their own environment. Released binaries already have it embedded; you don't need to (and can't) configure it yourself.

## Development

```bash
go mod tidy
make test    # run tests with race detection
make lint    # run golangci-lint
make check   # tidy, fmt, lint, test
```

See `make help` for all available targets.
