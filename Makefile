BINARY_NAME := zero-trust-auth-cli
DIST_DIR := dist
VERSION ?= dev

GO ?= go
GOFLAGS ?=
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all release windows macos-arm linux-x86_64 linux-amd64 test clean

all: release

release: windows macos-arm linux-x86_64

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

windows: $(DIST_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe .

macos-arm: $(DIST_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 .

linux-x86_64: $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 .

linux-amd64: linux-x86_64

test:
	$(GO) test ./...

clean:
	rm -rf $(DIST_DIR)
