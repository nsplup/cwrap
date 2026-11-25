package run

import (
	"strings"
	"testing"

	"cwrap/internal/perm"
)

func TestDbusNameSegment(t *testing.T) {
	cases := []struct{ in, want string }{
		{"demo", "demo"},
		{"My App!", "my-app"},
		{"com.example.App", "com-example-app"}, // 段内点号折叠为连字符
		{"123app", "app-123app"},
		{"", "app-"},
		{"游戏", "app-"},
	}
	for _, c := range cases {
		if got := dbusNameSegment(c.in); got != c.want {
			t.Fatalf("dbusNameSegment(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFlatpakAppName(t *testing.T) {
	p := perm.Default()
	if got := flatpakAppName(p); got != "org.cwrap.Sandbox" {
		t.Fatalf("无应用名应回退: %s", got)
	}
	p.App = "demo"
	if got := flatpakAppName(p); got != "org.cwrap.App.demo" {
		t.Fatalf("按应用独立 name 失败: %s", got)
	}
}

func TestGenerateFlatpakInfo(t *testing.T) {
	p := perm.Default()
	p.App = "demo"
	p.Share = []string{"network"}
	p.Socket = []string{"x11", "wayland"}
	p.Device = []string{"dri"}
	p.FS = []string{"ro:/opt/data"}
	p.DBus = []string{"preset:portal", "session.own=org.example.Demo", "system.talk=org.example.S"}

	info := generateFlatpakInfo(p, "abc123")
	for _, want := range []string{
		"name=org.cwrap.App.demo",
		"instance-id=abc123",
		"shared=network;",
		"sockets=x11;wayland;",
		"devices=dri;",
		"filesystems=ro:/opt/data;",
		// portal 预设展开后的 talk 规则进入 Session Bus Policy
		"org.freedesktop.portal.*=talk",
		"org.example.Demo=own",
		"[System Bus Policy]",
		"org.example.S=talk",
	} {
		if !strings.Contains(info, want) {
			t.Fatalf(".flatpak-info 缺少 %q:\n%s", want, info)
		}
	}
	// call/broadcast 不属于 policy 节
	if strings.Contains(info, "call") {
		t.Fatalf("policy 节不应包含 call 规则:\n%s", info)
	}
}

func TestGenerateFlatpakInfoUniqueInstanceID(t *testing.T) {
	a := generateFlatpakInfo(perm.Default(), newInstanceID())
	b := generateFlatpakInfo(perm.Default(), newInstanceID())
	if strings.Contains(a, "instance-id=cwrap") {
		t.Fatal("不应出现旧固定 instance-id")
	}
	id1 := strings.SplitN(strings.SplitN(a, "instance-id=", 2)[1], "\n", 2)[0]
	id2 := strings.SplitN(strings.SplitN(b, "instance-id=", 2)[1], "\n", 2)[0]
	if id1 == id2 {
		t.Fatalf("instance-id 应唯一: %s", id1)
	}
}
