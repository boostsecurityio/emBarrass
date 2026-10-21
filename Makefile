SHELL=/usr/bin/env bash
.SHELLFLAGS=-o pipefail -ec
.DEFAULT_GOAL := test

.PHONY: build install test test-race format lint
build:
	go build -trimpath -o embarass ./cmd/embarass

install:
	@install_dir="$(GOBIN)"; \
	if [[ -z "$$install_dir" ]]; then install_dir="$$(go env GOBIN)"; fi; \
	if [[ -z "$$install_dir" ]]; then install_dir="$$(go env GOPATH)/bin"; fi; \
	GOBIN="$$install_dir" go install -trimpath ./cmd/embarass; \
	printf 'Installed %s\n' "$$install_dir/embarass"; \
	if [[ ":$$PATH:" != *":$$install_dir:"* ]]; then \
		printf 'Add %s to PATH to run embarass directly.\n' "$$install_dir"; \
	fi

test:
	go test ./... -cover

test-race:
	go test -race -count=1 ./...

format:
	go fmt ./...

lint:
	golangci-lint run
