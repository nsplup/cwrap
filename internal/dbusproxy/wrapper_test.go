package dbusproxy

import (
	"strings"
	"testing"
)

// 包装层参数对齐 flatpak add_bwrap_wrapper：根目录 ro 挂、tmp/var/run rw、
// socket 目录 rw、/.flatpak-info 以 --ro-bind-data 0600 提供；
// 不携带 --sync-fd（生命周期统一由 cwrap 以 --die-with-parent 保证）。
func TestDbusProxyWrapperArgs(t *testing.T) {
	args := dbusProxyWrapperArgs("/run/user/1000/cwrap/org.cwrap.App.demo/test123", 6)
	joined := strings.Join(args, "\x00")
	for _, want := range []string{
		"--bind-try\x00/tmp\x00/tmp",
		"--bind-try\x00/var\x00/var",
		"--bind-try\x00/run\x00/run",
		"--ro-bind-try\x00/usr\x00/usr",
		"--bind-try\x00/run/user/1000/cwrap/org.cwrap.App.demo/test123\x00/run/user/1000/cwrap/org.cwrap.App.demo/test123",
		"--perms\x000600",
		"--ro-bind-data\x006\x00/.flatpak-info",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("包装参数缺少 %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "--sync-fd") {
		t.Fatal("包装参数不应再携带 --sync-fd")
	}
	if strings.Contains(joined, "/.flatpak-info\x00/.flatpak-info") {
		t.Fatal("宿主根上的 .flatpak-info 不应被 ro-bind（跳过以 --ro-bind-data 提供）")
	}
}
