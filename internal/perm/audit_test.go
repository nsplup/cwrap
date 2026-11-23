package perm

import "testing"

// 关键字锚点展开禁止上溯出锚点目录；绝对路径归一化后指向 "/" 必须被拒。
func TestResolveFSPathTraversalGuard(t *testing.T) {
	bad := []string{
		"/usr/../",             // Clean 后为 "/"：曾绕过根目录禁令
		"/proc/../",            // 同上
		"/tmp/..",              // 同上
		"xdg-run/../",          // 上溯出 $XDG_RUNTIME_DIR（含宿主 bus socket）
		"xdg-config/../../etc", // 多级上溯
		"home/../../etc",       // 上溯出 $HOME
		"~/../",                // 同上
	}
	for _, b := range bad {
		_, _, err := ResolveFSPath(b)
		if err == nil {
			t.Fatalf("--fs %q 应被拒绝", b)
		}
	}
	ok := []string{
		"/opt/data",      // 绝对路径合法
		"xdg-run/doc",    // 关键字合法子路径
		"home/Downloads", // home 子路径
		"~/.config",      // ~ 子路径
		"host",           // host 关键字
		"/a/b/../c",      // 归一化后非 "/"，合法
	}
	for _, g := range ok {
		if _, _, err := ResolveFSPath(g); err != nil {
			t.Fatalf("--fs %q 不应被拒绝: %v", g, err)
		}
	}
}

// App 名与 home 路径校验。
func TestValidateAppAndHome(t *testing.T) {
	for _, bad := range []string{"../evil", "a/b", "a/b.toml", ".hidden"} {
		p := Default()
		p.App = bad
		if err := p.Validate(); err == nil {
			t.Fatalf("App %q 应被拒绝", bad)
		}
	}
	for _, good := range []string{"demo", "my-app_2", "com.example.app"} {
		p := Default()
		p.App = good
		if err := p.Validate(); err != nil {
			t.Fatalf("App %q 不应被拒绝: %v", good, err)
		}
	}
	for _, bad := range []string{"/", "/usr", "/etc", "/var", "/proc", "/sys", "/dev", "/run", "/boot", "/root", "relative/path"} {
		p := Default()
		p.Home = bad
		if err := p.Validate(); err == nil {
			t.Fatalf("HomeDir %q 应被拒绝", bad)
		}
	}
	p := Default()
	p.Home = "/home/z/.var/sandbox/demo"
	if err := p.Validate(); err != nil {
		t.Fatalf("专用 home 目录不应被拒绝: %v", err)
	}
}

// "-" 前缀的 D-Bus 透传 token 不经 target 校验。
func TestDbusRulesDashPassthrough(t *testing.T) {
	p := Default()
	p.DBus = []string{"session.talk=org.freedesktop.Notifications", "--log"}
	rules, err := p.DbusRules()
	if err != nil {
		t.Fatalf("--dbus-arg 透传 token 不应报错: %v", err)
	}
	_ = rules
}
