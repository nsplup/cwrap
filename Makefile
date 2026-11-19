# 构建 & 测试
GO ?= go

# 版本号：commit 提交日期（YYYY.MM.DD）+ 6 位短哈希。
# 无 .git（tar 包构建）时回退到 internal/version 中的内置值。
GIT_DATE := $(shell git log -1 --date=format:'%Y.%m.%d' --format=%cd 2>/dev/null)
GIT_HASH := $(shell git rev-parse --short=6 HEAD 2>/dev/null)
VERSION := $(GIT_DATE)+$(GIT_HASH)
ifeq ($(VERSION),-)
        VERSION =
endif
ifneq ($(VERSION),)
        LDFLAGS_VERSION := -X cwrap/internal/version.Value=$(VERSION)
endif

.PHONY: build test smoke

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w $(LDFLAGS_VERSION)" -o cwrap ./cmd/cwrap

test:
	$(GO) test ./internal/...

smoke: build
	./scripts/smoke-test.sh

package: build
	tar -czf cwrap-linux-amd64.tar.gz cwrap README.md docs/
