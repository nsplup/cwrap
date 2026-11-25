package bwrap

import (
	"strings"
	"testing"

	"cwrap/internal/perm"
)

// 生命周期同步：SyncFD > 0 时携带 --sync-fd，且不再使用 --die-with-parent
// （沙箱生命周期由 cwrap 主进程持有的 sync 管道写端决定）。
func TestSyncFDReplacesDieWithParent(t *testing.T) {
	args, err := Args(&Options{
		Perm:    perm.Default(),
		UID:     1000,
		HomeDir: t.TempDir(),
		SyncFD:  9,
		CmdPath: "/bin/true",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\x00")
	if !strings.Contains(joined, "--sync-fd\x009") {
		t.Fatalf("缺少 --sync-fd 9:\n%s", joined)
	}
	if strings.Contains(joined, "--die-with-parent") {
		t.Fatal("不应再使用 --die-with-parent")
	}
}

// SyncFD 为 0（单元测试拼参场景）时不携带 --sync-fd。
func TestNoSyncFDWhenZero(t *testing.T) {
	args, err := Args(&Options{
		Perm:    perm.Default(),
		UID:     1000,
		HomeDir: t.TempDir(),
		CmdPath: "/bin/true",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(args, "\x00"), "--sync-fd") {
		t.Fatal("SyncFD=0 不应出现 --sync-fd")
	}
}
