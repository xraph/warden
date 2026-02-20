.PHONY: all build test lint fmt tidy clean

GO     := go
GOBIN  := $(shell go env GOPATH)/bin
MODULE := github.com/xraph/warden

all: build test lint

build:
	$(GO) build ./...

test:
	$(GO) test -race -count=1 ./...

test-cover:
	$(GO) test -race -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

lint:
	@which golangci-lint > /dev/null || (echo "golangci-lint not found, install via https://golangci-lint.run/usage/install/"; exit 1)
	golangci-lint run --timeout 10m

fmt:
	gofmt -w .
	goimports -w -local $(MODULE) .

tidy:
	$(GO) mod tidy

clean:
	rm -f coverage.out coverage.html

.PHONY: gen
gen:
	$(GO) generate ./...
