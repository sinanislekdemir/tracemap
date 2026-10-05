# Traceroute Map — native desktop app (Go + Qt6 via miqt)
#
# The UI is Qt6 Widgets. It renders the offline vector map itself with QPainter
# (see internal/mapview), so there is no web engine, tile server or Node build.
# You need the Qt6 development packages; `make sysdeps` checks for them.

SHELL := /bin/bash
.DEFAULT_GOAL := help

APP := traceroute
BIN := build/bin/$(APP)
GO  := go

# Apple Clang defaults to gnu++98, but Qt6's headers (and the miqt bindings)
# require C++17. GCC and clang elsewhere already default to C++17, so this is
# only needed on macOS.
ifeq ($(shell uname -s),Darwin)
export CGO_CXXFLAGS := -O2 -g -std=c++17
endif

## help: show this help
.PHONY: help
help:
	@echo "Traceroute Map — make targets:"
	@echo
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /' | column -t -s ':'
	@echo
	@echo "  Qt: $$(pkg-config --modversion Qt6Widgets 2>/dev/null || echo 'not found')"

## sysdeps: verify Qt6 build dependencies
.PHONY: sysdeps
sysdeps:
	@missing=0; \
	if pkg-config --exists Qt6Widgets 2>/dev/null; then echo "  ok   Qt6Widgets $$(pkg-config --modversion Qt6Widgets)"; else echo "  MISS Qt6Widgets"; missing=1; fi; \
	if command -v g++ >/dev/null 2>&1; then echo "  ok   g++"; else echo "  MISS g++"; missing=1; fi; \
	if [ "$$(go env CGO_ENABLED)" = "1" ]; then echo "  ok   cgo"; else echo "  MISS cgo (CGO_ENABLED=0)"; missing=1; fi; \
	if [ $$missing -ne 0 ]; then \
	  echo; echo "Install Qt6 development packages:"; \
	  echo "  Fedora:  sudo dnf install -y qt6-qtbase-devel gcc-c++"; \
	  echo "  Debian:  sudo apt-get install -y qt6-base-dev g++"; \
	  echo "  macOS:   brew install qt"; \
	  exit 1; \
	fi

## deps: download Go modules
.PHONY: deps
deps:
	$(GO) mod download

## build: compile the release binary into build/bin/
.PHONY: build
build:
	@mkdir -p build/bin
	$(GO) build -trimpath -ldflags "-s -w" -o $(BIN) .

## run: build, then launch the app
.PHONY: run
run: build
	$(BIN)

## dev: run the app directly from source
.PHONY: dev
dev:
	$(GO) run .

## test: run Go tests
.PHONY: test
test:
	$(GO) test ./...

## vet: run go vet
.PHONY: vet
vet:
	$(GO) vet ./...

## fmt: format Go sources
.PHONY: fmt
fmt:
	$(GO) fmt ./...

## tidy: tidy go.mod/go.sum
.PHONY: tidy
tidy:
	$(GO) mod tidy

## check: vet + test + build
.PHONY: check
check: vet test build

## clean: remove build artifacts
.PHONY: clean
clean:
	rm -rf build/bin
