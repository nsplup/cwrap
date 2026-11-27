package bwrap

import (
	"strings"
	"testing"

	"cwrap/internal/perm"
)

// 生命周期同步：始终携带 --die-with-parent（内核 PR_SET_PDEATHSIG 保证
// cwrap 主进程退出即沙箱被 SIGKILL 回收），且不再使用 --sync-fd
// （bwrap 对该 fd 只有"持有到沙箱退出"语义，无法承载生命周期同步）。
func TestDieWithParentAlways(t *testing.T) {
	args, err := Args(&Options{
		Perm:    perm.Default(),
		UID:     1000,
		HomeDir: t.TempDir(),
		CmdPath: "/bin/true",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\x00")
	if !strings.Contains(joined, "--die-with-parent") {
		t.Fatalf("缺少 --die-with-parent:\n%s", joined)
	}
	if strings.Contains(joined, "--sync-fd") {
		t.Fatal("不应再使用 --sync-fd")
	}
}
