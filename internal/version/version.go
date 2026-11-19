// Package version 存放构建时注入的版本号。
//
// 版本号格式：提交日期（YYYY.MM.DD）+ 6 位短哈希，例如 2026.11.19+f68ab7。
// Makefile 通过 ldflags 注入 git 生成的值；本文件的值是发布快照的
// fallback（源码 tar 包无 .git 时仍然可报告正确版本）。
package version

// Value 是当前版本号，构建时可被 ldflags 覆盖。
var Value = "2026.11.19+f68ab7"
