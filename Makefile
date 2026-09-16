# Traceroute Map — desktop app (Wails v2)
#
# Linux/WebKitGTK 4.1 note: this box has only webkit2gtk-4.1, so builds need the
# `webkit2_41` tag. It is auto-detected below and can be overridden with
# `make build WAILS_TAGS=`.

SHELL := /bin/bash
.DEFAULT_GOAL := help

APP    := traceroute
BIN    := build/bin/$(APP)
GO     := go
NPM    := npm
WAILS  ?= $(shell command -v wails 2>/dev/null || echo $(HOME)/go/bin/wails)

# Auto-detect the WebKitGTK flavour for the build tag.
WAILS_TAGS ?= $(if $(shell pkg-config --exists webkit2gtk-4.1 2>/dev/null && echo 1),webkit2_41,)
TAG_FLAG   := $(if $(WAILS_TAGS),-tags $(WAILS_TAGS),)

## help: show this help
.PHONY: help
help:
	@echo "Traceroute Map — make targets:"
	@echo
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /' | column -t -s ':'
	@echo
	@echo "  WAILS_TAGS = $(if $(WAILS_TAGS),$(WAILS_TAGS),(none))   WAILS = $(WAILS)"

## sysdeps: verify Linux build/runtime dependencies
.PHONY: sysdeps
sysdeps:
	@missing=0; \
	for p in webkit2gtk-4.1 gtk+-3.0; do \
	  if pkg-config --exists $$p 2>/dev/null; then echo "  ok   $$p"; else echo "  MISS $$p"; missing=1; fi; \
	done; \
	if command -v g++ >/dev/null 2>&1; then echo "  ok   g++"; else echo "  MISS g++"; missing=1; fi; \
	if [ $$missing -ne 0 ]; then \
	  echo; echo "Install with:"; \
	  echo "  sudo dnf install -y gcc-c++ gtk3-devel webkit2gtk4.1-devel"; \
	  exit 1; \
	fi

## check-wails: verify the Wails CLI is installed
.PHONY: check-wails
check-wails:
	@command -v $(WAILS) >/dev/null 2>&1 || { \
	  echo "wails CLI not found at '$(WAILS)'."; \
	  echo "Install: go install github.com/wailsapp/wails/v2/cmd/wails@latest"; \
	  exit 1; }

## deps: download Go modules and install frontend packages
.PHONY: deps
deps:
	$(GO) mod download
	$(NPM) --prefix frontend install

## bindings: regenerate the JS/TS bindings from the Go backend
.PHONY: bindings
bindings: check-wails
	$(WAILS) generate module

## dev: run the app with hot reload
.PHONY: dev
dev: check-wails
	$(WAILS) dev $(TAG_FLAG)

## build: produce the release binary in build/bin/
.PHONY: build
build: check-wails
	$(WAILS) build $(TAG_FLAG)

## run: build, then launch the app
.PHONY: run
run: build
	$(BIN)

## test: run Go tests
.PHONY: test
test:
	$(GO) test $(TAG_FLAG) ./...

## vet: run go vet
.PHONY: vet
vet:
	$(GO) vet $(TAG_FLAG) ./...

## fmt: format Go sources
.PHONY: fmt
fmt:
	$(GO) fmt ./...

## tidy: tidy go.mod/go.sum
.PHONY: tidy
tidy:
	$(GO) mod tidy

## typecheck: type-check the frontend
.PHONY: typecheck
typecheck:
	$(NPM) --prefix frontend run typecheck

## check: vet + test + typecheck
.PHONY: check
check: vet test typecheck

## clean: remove build artifacts and the built frontend
.PHONY: clean
clean:
	rm -rf build/bin frontend/dist frontend/package.json.md5

## distclean: clean plus frontend node_modules
.PHONY: distclean
distclean: clean
	rm -rf frontend/node_modules
