package dbusproxy

import (
	"strings"
	"testing"

	"cwrap/internal/perm"
)

// 规则映射：talk/own/see/call/broadcast -> xdg-dbus-proxy 参数，且按总线过滤。
func TestDbusProxyArgsMapping(t *testing.T) {
	rules := []string{
		"session.talk=org.example.A",
		"session.own=org.example.B",
		"session.see=org.example.C",
		"session.call=org.example.D=org.example.D.*@/org/example/D",
		"session.broadcast=org.example.E=org.example.E.*@/org/example/E",
		"system.talk=org.freedesktop.Systemd",
	}
	sessionArgs, err := dbusProxyArgs(filterRules(rules, "session"))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(sessionArgs, "\x00")
	for _, want := range []string{
		"--talk=org.example.A", "--own=org.example.B", "--see=org.example.C",
		"--call=org.example.D=org.example.D.*@/org/example/D",
		"--broadcast=org.example.E=org.example.E.*@/org/example/E",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("session 参数缺少 %s", want)
		}
	}
	if strings.Contains(joined, "org.freedesktop.Systemd") {
		t.Fatalf("session 代理不应包含 system 规则")
	}

	systemArgs, err := dbusProxyArgs(filterRules(rules, "system"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(systemArgs, "\x00"), "--talk=org.freedesktop.Systemd") {
		t.Fatalf("system 参数缺少 talk 规则")
	}
	if strings.Contains(strings.Join(systemArgs, "\x00"), "org.example.A") {
		t.Fatalf("system 代理不应包含 session 规则")
	}
}

// --dbus-arg（"-" 前缀）原样透传。
func TestRawDBusArgsPassthrough(t *testing.T) {
	rules := []string{"--log", "session.talk=org.example.A"}
	args, err := dbusProxyArgs(filterRules(rules, "session"))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\x00")
	if !strings.Contains(joined, "--log") || !strings.Contains(joined, "--talk=org.example.A") {
		t.Fatalf("raw dbus 参数透传失败: %v", args)
	}
}

// 预设展开后经 NeedBuses 判断需要代理哪些总线。
func TestNeedBusesWithPresets(t *testing.T) {
	p := perm.Default()
	p.DBus = []string{"preset:notify"}
	session, system := NeedBuses(p)
	if !session || system {
		t.Fatalf("notify 预设应只启用 session: %v %v", session, system)
	}

	p2 := perm.Default()
	p2.Socket = []string{"session-bus"} // 直通
	p2.DBus = []string{"preset:notify"}
	s2, sys2 := NeedBuses(p2)
	if s2 || sys2 {
		t.Fatalf("直通 socket 不应启动代理: %v %v", s2, sys2)
	}
}
