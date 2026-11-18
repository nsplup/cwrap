# 构建 & 测试
GO ?= go

.PHONY: build test smoke

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o cwrap ./cmd/cwrap

test:
	$(GO) test ./internal/...

smoke: build
	./scripts/smoke-test.sh

package: build
	tar -czf cwrap-linux-amd64.tar.gz cwrap README.md docs/
