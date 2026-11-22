package perm

import (
	"strings"
	"testing"
)

// 否决语义：!value 从列表中整体移除（对齐 flatpak override）。
func TestApplyDenies(t *testing.T) {
	p := Default()
	p.Socket = []string{"x11", "wayland", "!wayland"}
	p.Share = []string{"network", "ipc"}
	p.Device = []string{"dri", "input"}
	p.DBus = []string{"session.talk=org.example.A"}
	p.FS = []string{"ro:/opt/data"}
	p.ApplyDenies()
	if !Has(p.Socket, "x11") || Has(p.Socket, "wayland") {
		t.Fatalf("socket 否决失败: %v", p.Socket)
	}
	if !Has(p.Share, "network") || !Has(p.Device, "dri") ||
		len(p.DBus) == 0 || len(p.FS) == 0 {
		t.Fatalf("无否决项的列表不应被改动: %v %v %v %v", p.Share, p.Device, p.DBus, p.FS)
	}

	p2 := Default()
	p2.Socket = []string{"x11", "!x11"}
	p2.ApplyDenies()
	if len(p2.Socket) != 0 {
		t.Fatalf("同层否决应清空: %v", p2.Socket)
	}
}

// 配置层授予 + FLAG 否决：后层否决前层。
func TestDenyAcrossLayers(t *testing.T) {
	p := Default()
	p.Socket = []string{"x11", "wayland"}
	flagged := Default()
	flagged.Socket = []string{"!x11"}
	m := Default()
	m.Overlay(p)
	m.Overlay(flagged)
	m.ApplyDenies()
	if Has(m.Socket, "x11") {
		t.Fatalf("后层否决未生效: %v", m.Socket)
	}
	if !Has(m.Socket, "wayland") {
		t.Fatalf("未否决项应保留: %v", m.Socket)
	}
}

// D-Bus 预设展开逐条对齐 bubblejail 规则集。
func TestExpandDbusPresets(t *testing.T) {
	got, err := ExpandDbusPresets([]string{"preset:notify"})
	if err != nil {
		t.Fatal(err)
	}
	if !inList(got, "session.talk=org.freedesktop.Notifications") ||
		!inList(got, "session.call=org.freedesktop.Notifications=org.freedesktop.Notifications.*@/org/freedesktop/Notifications") {
		t.Fatalf("notify 预设规则不符: %v", got)
	}

	mpris, err := ExpandDbusPresets([]string{"preset:mpris=firefox.*"})
	if err != nil || !inList(mpris, "session.own=org.mpris.MediaPlayer2.firefox.*") {
		t.Fatalf("mpris 预设失败: %v %v", mpris, err)
	}
	if _, err := ExpandDbusPresets([]string{"preset:mpris"}); err == nil {
		t.Fatal("mpris 缺少 glob 应报错")
	}
	if _, err := ExpandDbusPresets([]string{"preset:nope"}); err == nil {
		t.Fatal("未知预设应报错")
	}
	portal, _ := ExpandDbusPresets([]string{"preset:portal"})
	joined := strings.Join(portal, "\n")
	for _, want := range []string{
		// 对齐 flatpak：talk + 任意接口 call + /org/freedesktop/portal/* 广播
		"session.talk=org.freedesktop.portal.*",
		"session.call=org.freedesktop.portal.*=*",
		"session.broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("portal 预设缺少 %s", want)
		}
	}
}

// DbusRules 应先展开预设再解析。
func TestDbusRulesWithPreset(t *testing.T) {
	p := Default()
	p.DBus = []string{"preset:gamemode"}
	rules, err := p.DbusRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Target != "session.talk" {
		t.Fatalf("gamemode 预设解析失败: %+v", rules)
	}
}

// 新值域校验。
func TestValidateNewValues(t *testing.T) {
	p := Default()
	p.NetBackend = "pasta"
	p.Harden = []string{"namespaces", "sync"}
	p.Socket = []string{"session-bus", "gpg-agent"}
	p.Device = []string{"input", "v4l", "ntsync"}
	p.Allow = []string{"portal"}
	if err := p.Validate(); err != nil {
		t.Fatalf("新值域应合法: %v", err)
	}
	if p.UserNetBackend() != "pasta" {
		t.Fatal("net_backend 应保留")
	}

	p2 := Default()
	p2.NetBackend = "vpn"
	if err := p2.Validate(); err == nil {
		t.Fatal("非法 net_backend 应报错")
	}
	p3 := Default()
	p3.Harden = []string{"cheat"}
	if err := p3.Validate(); err == nil {
		t.Fatal("非法 harden 应报错")
	}
}

// host 默认后端。
func TestUserNetBackendDefault(t *testing.T) {
	if got := Default().UserNetBackend(); got != "host" {
		t.Fatalf("默认 net backend 应为 host: %s", got)
	}
}
