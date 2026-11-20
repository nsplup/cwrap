package bwrap

import (
        "strings"
        "testing"

        "cwrap/internal/perm"
)

func argHas(args []string, want ...string) bool {
        s := strings.Join(args, "\x00")
        return strings.Contains(s, "\x00"+strings.Join(want, "\x00"))
}

func baseOpts(t *testing.T, tmp string) *Options {
        t.Helper()
        p := perm.Default()
        p.App = "demo"
        p.Tmp = tmp
        return &Options{Perm: p, UID: 1000, HomeDir: t.TempDir()}
}

// 基线必须包含 --cap-drop ALL。
func TestBaselineCapDropAll(t *testing.T) {
        args, err := Args(baseOpts(t, "tmpfs"))
        if err != nil {
                t.Fatal(err)
        }
        if !argHas(args, "--cap-drop", "ALL") {
                t.Fatal("缺少 --cap-drop ALL")
        }
}

func TestTmpModes(t *testing.T) {
        // tmpfs：全空 --tmpfs /tmp
        a, err := Args(baseOpts(t, "tmpfs"))
        if err != nil {
                t.Fatal(err)
        }
        if !argHas(a, "--tmpfs", "/tmp") {
                t.Fatal("tmpfs 模式缺少 --tmpfs /tmp")
        }

        // host：--bind /tmp /tmp
        a, err = Args(baseOpts(t, "host"))
        if err != nil {
                t.Fatal(err)
        }
        if !argHas(a, "--bind", "/tmp", "/tmp") {
                t.Fatal("host 模式缺少 --bind /tmp /tmp")
        }
}

// fs 关键字展开：ro:xdg-download? 应展开为宿主 XDG 下载目录并使用 --ro-bind-try。
func TestFSKeywordExpansion(t *testing.T) {
        o := baseOpts(t, "tmpfs")
        o.Perm.FS = []string{"ro:xdg-download?", "rw:~/.hidden"}
        a, err := Args(o)
        if err != nil {
                t.Fatal(err)
        }
        joined := strings.Join(a, "\x00")
        if !strings.Contains(joined, "--ro-bind-try") {
                t.Fatal("? 后缀未生成 --ro-bind-try")
        }
        if !strings.Contains(joined, "/.hidden") {
                t.Fatal("~/ 子路径未展开")
        }
        if argHas(a, "--ro-bind", "xdg-download?", "xdg-download?") {
                t.Fatal("关键字未被展开")
        }
}

// host 模式下 /tmp 下的 fs 授权项应被兜底跳过。
func TestHostTmpDedup(t *testing.T) {
        o := baseOpts(t, "host")
        o.Perm.FS = []string{"ro:/tmp/sub", "rw:/opt"}
        a, err := Args(o)
        if err != nil {
                t.Fatal(err)
        }
        if argHas(a, "--ro-bind", "/tmp/sub", "/tmp/sub") {
                t.Fatal("host 模式未去重 /tmp 子路径")
        }
        if !argHas(a, "--bind", "/opt", "/opt") {
                t.Fatal("常规授权项丢失")
        }
}

// host 模式下 x11 的 /tmp/.X11-unix 挂载应跳过（已随 /tmp 可见）。
func TestX11BindDedup(t *testing.T) {
        o := baseOpts(t, "host")
        o.Perm.Socket = []string{"x11"}
        a, err := Args(o)
        if err != nil {
                t.Fatal(err)
        }
        if argHas(a, "--ro-bind-try", "/tmp/.X11-unix", "/tmp/.X11-unix") {
                t.Fatal("host 模式应跳过 /tmp/.X11-unix 重复挂载")
        }

        o2 := baseOpts(t, "tmpfs")
        o2.Perm.Socket = []string{"x11"}
        a2, err := Args(o2)
        if err != nil {
                t.Fatal(err)
        }
        if !argHas(a2, "--ro-bind-try", "/tmp/.X11-unix", "/tmp/.X11-unix") {
                t.Fatal("tmpfs 模式仍需挂载 /tmp/.X11-unix")
        }
}
