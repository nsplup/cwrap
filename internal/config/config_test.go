package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProgramDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir) // Dir() 尊重 XDG_CONFIG_HOME
	prog, err := LoadProgram()
	if err != nil {
		t.Fatal(err)
	}
	if prog.BwrapCmd() != DefaultBwrapCmd {
		t.Fatalf("未配置时 bwrap 应按 PATH 查找: %s", prog.BwrapCmd())
	}
	if prog.DBusProxyCmd() != DefaultDBusProxyCmd {
		t.Fatalf("未配置时 xdg-dbus-proxy 应按 PATH 查找: %s", prog.DBusProxyCmd())
	}
}

func TestLoadProgramCustom(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	cfgDir := filepath.Join(dir, "cwrap")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "bwrap_path = \"/opt/bin/bwrap\"\nxdg_dbus_proxy_path = \"/opt/bin/xdg-dbus-proxy\"\n"
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := LoadProgram()
	if err != nil {
		t.Fatal(err)
	}
	if prog.BwrapCmd() != "/opt/bin/bwrap" || prog.DBusProxyCmd() != "/opt/bin/xdg-dbus-proxy" {
		t.Fatalf("自定义路径未生效: %+v", prog)
	}
}

func TestLoadProgramXDGOpen(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	cfgDir := filepath.Join(dir, "cwrap")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "xdg_open_path = \"/opt/flatpak-xdg-utils/xdg-open\"\n"
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := LoadProgram()
	if err != nil {
		t.Fatal(err)
	}
	if prog.XDGOpenPath != "/opt/flatpak-xdg-utils/xdg-open" {
		t.Fatalf("xdg_open_path 未生效: %q", prog.XDGOpenPath)
	}

	// 未配置时为空（自动探测）
	if err := os.Remove(filepath.Join(cfgDir, "config.toml")); err != nil {
		t.Fatal(err)
	}
	prog, err = LoadProgram()
	if err != nil {
		t.Fatal(err)
	}
	if prog.XDGOpenPath != "" {
		t.Fatalf("未配置时 xdg_open_path 应为空: %q", prog.XDGOpenPath)
	}
}
