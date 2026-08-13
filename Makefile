.PHONY: fmt tidy build test lint check

# Format all Go source (gofmt); golangci-lint's formatters also cover goimports.
fmt:
	gofmt -w .

# Keep go.mod/go.sum honest.
tidy:
	go mod tidy

build:
	go build ./...
	go build -o bin/ ./cmd/...

# All tests, no skips.
test:
	go test ./...

lint:
	golangci-lint run

# The one gate to run before every commit: everything green.
check: fmt tidy build test lint
