package cli

import (
	"bytes"
	"strings"
	"testing"

	"cwrap/internal/perm"
)

func mustFlagPerm(t *testing.T, args ...string) (*perm.Permissions, []string, []string, bool, bool, bool) {
	t.Helper()
	p, rest, pos, noGlobal, persist, dry, err := flagPerm(args)
	if err != nil {
		t.Fatalf("flagPerm(%v) 失败: %v", args, err)
	}
	return p, rest, pos, noGlobal, persist, dry
}

func joinList(l []string) string { return strings.Join(l, ",") }

// 基本解析：重复 FLAG、逗号分隔、-- 停止解析、布尔 FLAG。
func TestFlagPermBasic(t *testing.T) {
	p, rest, pos, noGlobal, persist, dry := mustFlagPerm(t,
		"--app", "demo", "--share", "network,ipc", "--share", "ipc",
		"--device", "dri", "--fs", "ro:/opt", "--fs", "rw:/data",
		"--no-global", "--persist", "--dry-run",
		"--", "/bin/true", "-x",
	)
	if p.App != "demo" {
		t.Fatalf("--app 解析失败: %q", p.App)
	}
	// flagPerm 阶段仅累加，去重由 OverlayList/ApplyDenies 完成
	if got := joinList(p.Share); got != "network,ipc,ipc" {
		t.Fatalf("--share 解析失败: %v", p.Share)
	}
	if got := joinList(p.Device); got != "dri" {
		t.Fatalf("--device 解析失败: %v", p.Device)
	}
	if got := joinList(p.FS); got != "ro:/opt,rw:/data" {
		t.Fatalf("--fs 解析失败: %v", p.FS)
	}
	if joinList(rest) != "/bin/true,-x" {
		t.Fatalf("-- 后命令应原样保留: %v", rest)
	}
	if len(pos) != 0 {
		t.Fatalf("位置参数应为空: %v", pos)
	}
	if !noGlobal || !persist || !dry {
		t.Fatalf("布尔 FLAG 解析失败: noGlobal=%v persist=%v dry=%v", noGlobal, persist, dry)
	}
}

// 位置参数与 FLAG 混排（permission export 的两种写法都应正确）。
func TestFlagPermPositional(t *testing.T) {
	_, rest, pos, _, _, _ := mustFlagPerm(t, "demo", "--fs", "rw:/x")
	if joinList(pos) != "demo" || len(rest) != 0 {
		t.Fatalf("FLAG 后置写法解析失败: pos=%v rest=%v", pos, rest)
	}
	_, rest, pos, _, _, _ = mustFlagPerm(t, "--fs", "rw:/x", "demo")
	if joinList(pos) != "demo" || len(rest) != 0 {
		t.Fatalf("FLAG 前置写法解析失败: pos=%v rest=%v", pos, rest)
	}
}

// 否决 FLAG 转换为 "!" 前缀进入对应列表。
func TestFlagPermDenyFlags(t *testing.T) {
	p, _, _, _, _, _ := mustFlagPerm(t, "--device", "dri", "--no-device", "dri",
		"--no-socket", "x11", "--no-fs", "ro:/opt", "--unset-env", "SECRET")
	if got := joinList(p.Device); got != "dri,!dri" {
		t.Fatalf("--no-device 应转为否决标记: %v", p.Device)
	}
	if got := joinList(p.Socket); got != "!x11" {
		t.Fatalf("--no-socket 应转为否决标记: %v", p.Socket)
	}
	if got := joinList(p.FS); got != "!ro:/opt" {
		t.Fatalf("--no-fs 应转为否决标记: %v", p.FS)
	}
	if got := joinList(p.UnsetEnv); got != "SECRET" {
		t.Fatalf("--unset-env 解析失败: %v", p.UnsetEnv)
	}
}

// --no-env 已移除：与 --unset-env 重复，应作为未知 FLAG 报错。
func TestNoEnvFlagRemoved(t *testing.T) {
	_, _, _, _, _, _, err := flagPerm([]string{"--no-env", "FOO=1"})
	if err == nil {
		t.Fatal("--no-env 已移除，应报未知 FLAG 错误")
	}
}

// 授权 FLAG 拒绝 "!" 前缀值，并提示正确的否决通道。
func TestAuthFlagRejectsDenyPrefix(t *testing.T) {
	cases := []struct {
		args []string
		want string // 错误信息中必须包含的通道提示
	}{
		{[]string{"--device", "!dri"}, "--no-device"},
		{[]string{"--socket", "!x11"}, "--no-socket"},
		{[]string{"--env", "!FOO=1"}, "--unset-env"},
		{[]string{"--unset-env", "!FOO"}, "配置文件"},
		{[]string{"--fs", "!ro:/opt"}, "--no-fs"},
	}
	for _, c := range cases {
		_, _, _, _, _, _, err := flagPerm(c.args)
		if err == nil {
			t.Fatalf("%v 应报否决前缀错误", c.args)
		}
		if !strings.Contains(err.Error(), "授权 FLAG 不能携带否决前缀") ||
			!strings.Contains(err.Error(), c.want) {
			t.Fatalf("%v 错误信息缺少通道提示 %q: %v", c.args, c.want, err)
		}
	}
}

// mergeFlags 优先级：FLAG 授权覆盖配置否决，FLAG 否决收窄配置授权。
func TestMergeFlagsPriority(t *testing.T) {
	base := perm.Default()
	base.Device = []string{"!dri"}
	base.Socket = []string{"x11"}

	flags, _, _, _, _, _ := mustFlagPerm(t, "--device", "dri", "--no-socket", "x11")
	merged, err := mergeFlags(base, flags)
	if err != nil {
		t.Fatalf("mergeFlags 失败: %v", err)
	}
	if got := joinList(merged.Device); got != "dri" {
		t.Fatalf("FLAG 授权应覆盖配置否决: %v", merged.Device)
	}
	if got := joinList(merged.Socket); got != "" {
		t.Fatalf("FLAG 否决应收窄配置授权: %v", merged.Socket)
	}
}

// mergeFlags 在结算否决前校验否决值：吞掉的非法值应报错。
func TestMergeFlagsRejectsBadDenyValue(t *testing.T) {
	flags, _, _, _, _, _ := mustFlagPerm(t, "--no-device", "--dry-run")
	if got := joinList(flags.Device); got != "!--dry-run" {
		t.Fatalf("否决 FLAG 吞值后应得到否决标记: %v", flags.Device)
	}
	if _, err := mergeFlags(perm.Default(), flags); err == nil ||
		!strings.Contains(err.Error(), `无效的 --device 否决值 "--dry-run"`) {
		t.Fatalf("否决 FLAG 吞掉后续 FLAG 应报非法否决值: %v", err)
	}

	flags2, _, _, _, _, _ := mustFlagPerm(t, "--no-fs", "--dry-run")
	if _, err := mergeFlags(perm.Default(), flags2); err == nil {
		t.Fatal("--no-fs 吞值应报非法否决值")
	}
}

// 合法否决值正常通过。
func TestMergeFlagsValidDeny(t *testing.T) {
	flags, _, _, _, _, _ := mustFlagPerm(t, "--device", "dri", "--no-device", "dri")
	merged, err := mergeFlags(perm.Default(), flags)
	if err != nil {
		t.Fatalf("mergeFlags 失败: %v", err)
	}
	if got := joinList(merged.Device); got != "" {
		t.Fatalf("同层否决应优先于授权: %v", merged.Device)
	}
}

// help 文本：覆盖新增的优先级/否决说明，且不再出现 --no-env。
func TestUsageText(t *testing.T) {
	var buf bytes.Buffer
	usageTo(&buf)
	text := buf.String()
	for _, want := range []string{
		"用法", "cwrap run [FLAGS] --",
		"--unset-env NAME", "--no-share", "--no-dbus", "--dry-run",
		"优先级与否决", "--unset-env 或配置文件",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("help 缺少 %q", want)
		}
	}
	if strings.Contains(text, "--no-env") {
		t.Fatal("help 不应再出现 --no-env")
	}
}
