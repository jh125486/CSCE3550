.PHONY: help init deps-update test tidy static lint lint-update vuln-check modernize outdated fmt vet check
.DEFAULT_GOAL := help

# Variables
BINARY_NAME := gradebot
BUILD_DIR := bin

## help: Show this help message
help:
	@echo "Available targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

## init: Initialize complete development environment (git hooks)
init: 
	@echo "Initializing development environment..."
	@bash .githooks/install-hooks.sh
	@go install golang.org/x/tools/cmd/goimports@latest
	@echo "Development environment initialized ✓"

deps-update: lint-update
	@echo "Updating Go modules to latest versions..."
	@go get -u -t ./...
	@go mod tidy
	@echo "Go modules updated ✓"

## test: Run all tests with coverage
test:
	@echo "Running tests..."
	@go test -timeout 30s -race -coverprofile=coverage.out ./...

tidy:
	@echo "Tidying Go modules..."
	@go mod tidy
	@echo "Go modules tidied ✓"

## static: Run all linting tools
static: tidy vet lint modernize vuln-check outdated
	@echo "All linting completed ✓"

## lint: Run golangci-lint with auto-fix enabled
lint:
	@echo "Running $$(go tool -modfile=golangci-lint.mod golangci-lint version)..."
	@go tool -modfile=golangci-lint.mod golangci-lint run --fix ./...

## lint-update: Update golangci-lint to latest version
lint-update:
	@echo "Updating golangci-lint..."
	@go get -tool -modfile=golangci-lint.mod github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	@go mod tidy -modfile=golangci-lint.mod
	@echo "Updated $$(go tool -modfile=golangci-lint.mod golangci-lint version)"

vuln-check:
	@echo "Checking for vulnerabilities..."
	@go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## modernize: Check for outdated Go patterns and suggest improvements
modernize:
	@echo "Running modernize analysis..."
	@go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -fix -test ./...
	
outdated:
	@echo "Checking for outdated direct dependencies..."
	@go list -u -m -f '{{if not .Indirect}}{{.}}{{end}}' all 2>/dev/null | grep '\[' || echo "All direct dependencies are up to date"

## fmt: Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@go run golang.org/x/tools/cmd/goimports@latest -w .

## vet: Run go vet
vet:
	@echo "Running go vet..."
	@go vet ./...

## check: Run all checks (format, vet, lint, test)
check: tidy fmt static test
	@echo "All checks completed ✓"

