package perm

import (
	"strings"
	"testing"
)

func TestResolveFSPathKeywords(t *testing.T) {
	home := userHome()
	cases := []struct {
		raw  string
		want []string
	}{
		{"home", []string{home}},
		{"~", []string{home}},
		{"~/Documents", []string{home + "/Documents"}},
		{"host-os", []string{"/usr"}},
		{"host-etc", []string{"/etc"}},
	}
	for _, c := range cases {
		got, try, err := ResolveFSPath(c.raw)
		if err != nil {
			t.Fatalf("%s: %v", c.raw, err)
		}
		if try {
			t.Fatalf("%s: 不应带 ?", c.raw)
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Fatalf("%s: got %v want %v", c.raw, got, c.want)
		}
	}
}

func TestResolveFSPathTrySuffix(t *testing.T) {
	_, try, err := ResolveFSPath("home?")
	if err != nil || !try {
		t.Fatalf("try=%v err=%v", try, err)
	}
}

func TestResolveFSPathHost(t *testing.T) {
	got, _, err := ResolveFSPath("host")
	if err != nil || len(got) < 2 {
		t.Fatalf("host: got %v err %v", got, err)
	}
	banned := map[string]bool{"/proc": true, "/sys": true, "/dev": true, "/usr": true, "/etc": true, "/run": true, "/tmp": true, "/": true}
	for _, p := range got {
		if banned[p] {
			t.Fatalf("host 不应包含 %s", p)
		}
		if !strings.HasPrefix(p, "/") {
			t.Fatalf("host 项必须是绝对路径: %s", p)
		}
	}
}

func TestResolveFSPathXdg(t *testing.T) {
	got, _, err := ResolveFSPath("xdg-run/sub")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got[0], "/run/user/") && !strings.HasPrefix(got[0], "/tmp/") {
		t.Fatalf("xdg-run 展开异常: %v", got)
	}
}

func TestFSPathValidRejects(t *testing.T) {
	for _, bad := range []string{"/", "", "app", "xdg-unknown"} {
		if err := FSPathValid(bad); err == nil {
			t.Fatalf("%q 应拒绝", bad)
		}
	}
	if err := FSPathValid("/x?"); err != nil {
		t.Fatalf("/x? 应合法: %v", err)
	}
}

func TestParseTmp(t *testing.T) {
	for _, ok := range []string{"", "tmpfs", "host"} {
		if _, err := ParseTmp(ok); err != nil {
			t.Fatalf("%q 应合法: %v", ok, err)
		}
	}
	for _, bad := range []string{"sandbox", "sandbox:/var/tmp", "sandbox:relative", "/opt/data", "/tmp", "wrong", "bind:/x"} {
		if _, err := ParseTmp(bad); err == nil {
			t.Fatalf("%q 应拒绝", bad)
		}
	}
	ts, err := ParseTmp("")
	if err != nil || ts.Kind != "tmpfs" {
		t.Fatalf("空值默认应为 tmpfs: %+v %v", ts, err)
	}
}

func TestFilterTmpFSConflicts(t *testing.T) {
	// tmpfs 默认：/tmp 本身冲突，/tmp 子路径保留
	p := Default()
	p.FS = []string{"rw:/tmp", "ro:/tmp/sub", "rw:/opt"}
	fs, warns := FilterTmpFSConflicts(p)
	if len(fs) != 2 || fs[0] != "ro:/tmp/sub" || fs[1] != "rw:/opt" {
		t.Fatalf("过滤结果异常: %v", fs)
	}
	if len(warns) != 1 {
		t.Fatalf("应有一条警告: %v", warns)
	}

	// host：/tmp 子路径也冲突
	p2 := Default()
	p2.Tmp = "host"
	p2.FS = []string{"ro:/tmp/.X11-unix", "rw:/opt"}
	fs2, warns2 := FilterTmpFSConflicts(p2)
	if len(fs2) != 1 || fs2[0] != "rw:/opt" {
		t.Fatalf("host 过滤结果异常: %v", fs2)
	}
	if len(warns2) != 1 {
		t.Fatalf("host 应有一条警告: %v", warns2)
	}

	// tmpfs：子路径保留
	p3 := Default()
	p3.Tmp = "tmpfs"
	p3.FS = []string{"rw:/tmp/data"}
	fs3, _ := FilterTmpFSConflicts(p3)
	if len(fs3) != 1 {
		t.Fatalf("tmpfs 不应过滤子路径: %v", fs3)
	}
}

func TestOverlayList(t *testing.T) {
	// 累加并去重：仅去除完全重复的值，保持顺序
	got := OverlayList([]string{"network", "ipc"}, []string{"ipc", "network"})
	want := []string{"network", "ipc"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("OverlayList 结果异常: %v want %v", got, want)
	}

	// 新值追加在后
	got = OverlayList([]string{"network"}, []string{"ipc", "ipc"})
	if strings.Join(got, ",") != "network,ipc" {
		t.Fatalf("OverlayList 追加异常: %v", got)
	}

	// 空覆盖：仅对 base 去重
	got = OverlayList([]string{"a", "a", "b"}, nil)
	if strings.Join(got, ",") != "a,b" {
		t.Fatalf("OverlayList 空覆盖异常: %v", got)
	}

	// 高优先级授权覆盖低优先级否决
	got = OverlayList([]string{"!dri"}, []string{"dri"})
	if strings.Join(got, ",") != "dri" {
		t.Fatalf("高优先级授权应覆盖低优先级否决: %v", got)
	}

	// 高优先级否决收窄低优先级授权
	got = OverlayList([]string{"dri"}, []string{"!dri"})
	if strings.Join(got, ",") != "!dri" {
		t.Fatalf("高优先级否决应收窄低优先级授权: %v", got)
	}

	// 其他不同值仍累加去重
	got = OverlayList([]string{"!dri", "input"}, []string{"dri", "dri"})
	if strings.Join(got, ",") != "input,dri" {
		t.Fatalf("不同值应累加: %v", got)
	}

	// 同层内后项覆盖前项（否决优先于授权）
	got = OverlayList(nil, []string{"dri", "!dri"})
	if strings.Join(got, ",") != "!dri" {
		t.Fatalf("同层否决应优先: %v", got)
	}
}

// 分层合并的整体行为：全局 !dri 被应用配置 dri 覆盖，FLAG 否决仍可收窄。
func TestDenyPriorityAcrossLayers(t *testing.T) {
	// 全局 device=["!dri"] + 应用配置 device=["dri"] -> ["dri"]
	m := Default()
	m.Device = []string{"!dri"}
	app := Default()
	app.Device = []string{"dri"}
	m.Overlay(app)

	flags := Default()
	flags.Device = nil
	m.Overlay(flags)
	m.ApplyDenies()
	if strings.Join(m.Device, ",") != "dri" {
		t.Fatalf("应用配置授权应覆盖全局否决: %v", m.Device)
	}

	// FLAG 否决（更高优先级）仍可收窄配置授权
	m2 := Default()
	m2.Device = []string{"dri", "input"}
	m2.Overlay(func() *Permissions { p := Default(); p.Device = []string{"!dri"}; return p }())
	m2.ApplyDenies()
	if strings.Join(m2.Device, ",") != "input" {
		t.Fatalf("高优先级否决应移除 dri 而保留 input: %v", m2.Device)
	}

	// 更高优先级层（FLAG 层同理）的授权覆盖低优先级层否决
	m3 := Default()
	m3.Device = []string{"!dri"}
	m3.Overlay(func() *Permissions { p := Default(); p.Device = []string{"dri"}; return p }())
	m3.ApplyDenies()
	if strings.Join(m3.Device, ",") != "dri" {
		t.Fatalf("高优先级授权应覆盖低优先级否决: %v", m3.Device)
	}
}

// 否决项的值本身必须合法：--no-* 吞掉后续 FLAG 时应报错而非静默否决。
func TestValidateDenyValues(t *testing.T) {
	p := Default()
	p.Device = []string{"!--dry-run"}
	if err := p.ValidateDenyValues(); err == nil {
		t.Fatal("--device 否决非法值应报错")
	}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate 应拒绝非法否决值")
	}

	ok := Default()
	ok.Socket = []string{"!x11"}
	ok.Device = []string{"!dri"}
	ok.FS = []string{"!ro:/opt/data"}
	ok.DBus = []string{"!session.talk=org.example.A", "!preset:notify"}
	ok.Env = []string{"!GTK_THEME=Dark"}
	if err := ok.ValidateDenyValues(); err != nil {
		t.Fatalf("合法否决值不应报错: %v", err)
	}

	for _, bad := range []struct{ name, val string }{
		{"share", "!--dry-run"}, {"socket", "!nope"}, {"device", "!!x11"},
		{"allow", "!cheat"}, {"harden", "!nope"},
		{"fs", "!--dry-run"}, {"fs", "!rw:/"},
		{"dbus", "!--dry-run"}, {"dbus", "!session.talk="}, {"dbus", "!preset:nope"},
		{"env", "!--dry-run"}, {"env", "!=VALUE"},
	} {
		bp := Default()
		switch bad.name {
		case "share":
			bp.Share = []string{bad.val}
		case "socket":
			bp.Socket = []string{bad.val}
		case "device":
			bp.Device = []string{bad.val}
		case "allow":
			bp.Allow = []string{bad.val}
		case "harden":
			bp.Harden = []string{bad.val}
		case "fs":
			bp.FS = []string{bad.val}
		case "dbus":
			bp.DBus = []string{bad.val}
		case "env":
			bp.Env = []string{bad.val}
		}
		if err := bp.ValidateDenyValues(); err == nil {
			t.Fatalf("%s 否决值 %q 应报错", bad.name, bad.val)
		}
	}
}

func TestHomeDirHostFallback(t *testing.T) {
	// 无应用名时 HOME 默认 $HOME/.var/sandbox/home
	p := Default()
	p.App = ""
	home := p.HomeDirHost()
	if !strings.HasSuffix(home, "/.var/sandbox/home") {
		t.Fatalf("无应用名时 HOME 应为 $HOME/.var/sandbox/home: %s", home)
	}
	p.App = "demo"
	home = p.HomeDirHost()
	if !strings.HasSuffix(home, "/.var/sandbox/demo") {
		t.Fatalf("有应用名时 HOME 应为 $HOME/.var/sandbox/demo: %s", home)
	}
}

func TestParseFSKeyword(t *testing.T) {
	mode, path, err := ParseFS("ro:xdg-download?")
	if err != nil || mode != "ro" || path != "xdg-download?" {
		t.Fatalf("ParseFS 关键字失败: %s %s %v", mode, path, err)
	}
	if _, _, err := ParseFS("rw:host"); err != nil {
		t.Fatalf("rw:host 应合法: %v", err)
	}
	if _, _, err := ParseFS("rw:/"); err == nil {
		t.Fatal("rw:/ 应拒绝")
	}
}
