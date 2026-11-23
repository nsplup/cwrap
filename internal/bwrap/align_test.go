package bwrap

import (
	"os"
	"strings"
	"testing"
)

// 直通逃生门：session-bus 直接 bind 宿主总线，不经过代理。
func TestSessionBusDirect(t *testing.T) {
	o := baseOpts(t, "tmpfs")
	o.Perm.Socket = []string{"session-bus"}
	o.Perm.DBus = []string{"session.talk=org.example.X"} // 即使有规则也不代理
	a, err := Args(o)
	if err != nil {
		t.Fatal(err)
	}
	if !argHas(a, "--bind-try", "/run/user/1000/bus", "/run/user/1000/bus") {
		t.Fatalf("session-bus 直通 bind 缺失: %v", a)
	}
}

func TestSystemBusDirect(t *testing.T) {
	o := baseOpts(t, "tmpfs")
	o.Perm.Socket = []string{"system-bus"}
	a, err := Args(o)
	if err != nil {
		t.Fatal(err)
	}
	if !argHas(a, "--ro-bind-try", "/run/dbus/system_bus_socket", "/run/dbus/system_bus_socket") {
		t.Fatalf("system-bus 直通 bind 缺失")
	}
}

func TestGpgAgent(t *testing.T) {
	o := baseOpts(t, "tmpfs")
	o.Perm.Socket = []string{"gpg-agent"}
	a, err := Args(o)
	if err != nil {
		t.Fatal(err)
	}
	// 对齐 flatpak：仅只读绑定具体 agent socket 文件（目录不可写）
	if !argHas(a, "--ro-bind-try", "/run/user/1000/gnupg/S.gpg-agent", "/run/user/1000/gnupg/S.gpg-agent") ||
		!argHas(a, "--ro-bind-try", "/run/user/1000/gnupg/S.gpg-agent.extra", "/run/user/1000/gnupg/S.gpg-agent.extra") {
		t.Fatalf("gpg-agent 只读 socket 绑定缺失")
	}
	if argHas(a, "--bind-try", "/run/user/1000/gnupg", "/run/user/1000/gnupg") {
		t.Fatalf("gnupg 目录不应再以读写方式挂载（沙箱可删除/替换 agent socket）")
	}
}

// pulseaudio 精修：只挂 native socket（对齐 bubblejail pulse_audio 服务）。
func TestPulseaudioNativeOnly(t *testing.T) {
	o := baseOpts(t, "tmpfs")
	o.Perm.Socket = []string{"pulseaudio"}
	a, err := Args(o)
	if err != nil {
		t.Fatal(err)
	}
	if !argHas(a, "--bind-try", "/run/user/1000/pulse/native", "/run/user/1000/pulse/native") {
		t.Fatalf("pulse native bind 缺失")
	}
	if !argHas(a, "--setenv", "PULSE_SERVER", "unix:/run/user/1000/pulse/native") {
		t.Fatalf("PULSE_SERVER 环境缺失")
	}
}

// wayland 精修：宿主任意名 socket 统一挂为 wayland-0。
func TestWaylandRename(t *testing.T) {
	t.Setenv("WAYLAND_DISPLAY", "wayland-1")
	o := baseOpts(t, "tmpfs")
	o.Perm.Socket = []string{"wayland"}
	a, err := Args(o)
	if err != nil {
		t.Fatal(err)
	}
	if !argHas(a, "--ro-bind-try", "/run/user/1000/wayland-1", "/run/user/1000/wayland-0") {
		t.Fatalf("wayland socket 重挂缺失")
	}
	if !argHas(a, "--setenv", "WAYLAND_DISPLAY", "wayland-0") {
		t.Fatalf("WAYLAND_DISPLAY 应统一为 wayland-0")
	}
	if !argHas(a, "--setenv", "GDK_BACKEND", "wayland") {
		t.Fatalf("GDK_BACKEND 缺失")
	}
}

// x11 精修：XAUTHORITY 写路径隔离（对齐 bubblejail x11 服务）。
func TestX11XauthorityRewrite(t *testing.T) {
	t.Setenv("XAUTHORITY", "/tmp/host-xauth")
	o := baseOpts(t, "tmpfs")
	o.Perm.Socket = []string{"x11"}
	a, err := Args(o)
	if err != nil {
		t.Fatal(err)
	}
	if !argHas(a, "--ro-bind-try", "/tmp/host-xauth", "/tmp/.Xauthority") {
		t.Fatalf("XAUTHORITY 隔离挂载缺失")
	}
	if !argHas(a, "--setenv", "XAUTHORITY", "/tmp/.Xauthority") {
		t.Fatalf("XAUTHORITY 应改写为沙箱路径")
	}
}

// /sys 基线（对齐 bubblejail 默认服务）。
func TestSysBaseline(t *testing.T) {
	a, err := Args(baseOpts(t, "tmpfs"))
	if err != nil {
		t.Fatal(err)
	}
	if !argHas(a, "--dir", "/sys") || !argHas(a, "--ro-bind-try", "/sys/devices/system/cpu", "/sys/devices/system/cpu") {
		t.Fatalf("/sys 基线缺失")
	}
}

// 设备扩展：/dev/ntsync、/dev/video*（存在性依赖宿主，缺失时仅验证不崩）。
func TestDeviceExtensions(t *testing.T) {
	o := baseOpts(t, "tmpfs")
	o.Perm.Device = []string{"input", "v4l", "ntsync"}
	if _, err := os.Stat("/sys/class/input"); err != nil {
		t.Skip("宿主无 /sys/class/input，跳过 input 参数断言")
	}
	a, err := Args(o)
	if err != nil {
		t.Fatal(err)
	}
	if !argHas(a, "--dir", "/sys/class/input") {
		t.Fatalf("input sysfs 重建缺失")
	}
}

// --harden namespaces：去掉 cap-drop ALL + sh 包装器。
func TestHardenNamespaces(t *testing.T) {
	o := baseOpts(t, "tmpfs")
	o.Perm.Harden = []string{"namespaces"}
	a, err := Args(o)
	if err != nil {
		t.Fatal(err)
	}
	if argHas(a, "--cap-drop", "ALL") {
		t.Fatalf("harden namespaces 不应 cap-drop ALL（pid1 需写 /proc/sys/user 限额）")
	}
	if !argHas(a, "/bin/sh", "-c") {
		t.Fatalf("缺少 namespaces 加固包装器")
	}
	if !strings.Contains(strings.Join(a, "\x00"), "max_*_namespaces") {
		t.Fatalf("加固脚本缺少限额写入")
	}
}

// --unset-env 与 --bwrap-arg 透传。
func TestUnsetEnvAndRawArgs(t *testing.T) {
	o := baseOpts(t, "tmpfs")
	o.Perm.UnsetEnv = []string{"SECRET_TOKEN"}
	o.Perm.RawBwrap = []string{"--dev-bind", "/dev/null", "/dev/null"}
	a, err := Args(o)
	if err != nil {
		t.Fatal(err)
	}
	if !argHas(a, "--unset-env", "SECRET_TOKEN") {
		t.Fatalf("--unset-env 缺失")
	}
	if !argHas(a, "--dev-bind", "/dev/null", "/dev/null") {
		t.Fatalf("raw bwrap 参数缺失")
	}
}

// portal 权限包：伪 /.flatpak-info + GTK_USE_PORTAL + xdg-open 覆盖。
func TestPortalPackage(t *testing.T) {
	o := baseOpts(t, "tmpfs")
	o.Perm.Allow = []string{"portal"}
	o.FlatpakInfoFD = 7
	a, err := Args(o)
	if err != nil {
		t.Fatal(err)
	}
	if !argHas(a, "--ro-bind-data", "7", "/.flatpak-info") {
		t.Fatalf("伪 .flatpak-info 缺失")
	}
	if !argHas(a, "--setenv", "GTK_USE_PORTAL", "1") {
		t.Fatalf("GTK_USE_PORTAL 缺失")
	}
}

// 网络后端：resolv.conf 注入与 --info-fd。
func TestNetBackendArgs(t *testing.T) {
	o := baseOpts(t, "tmpfs")
	o.InfoFD = 8
	o.NetResolvFD = 9
	a, err := Args(o)
	if err != nil {
		t.Fatal(err)
	}
	if !argHas(a, "--info-fd", "8") {
		t.Fatalf("--info-fd 缺失")
	}
	if !argHas(a, "--ro-bind-data", "9", "/etc/resolv.conf") {
		t.Fatalf("DNS 注入缺失")
	}

	// pasta/slirp 后端必须强制独立 netns
	o2 := baseOpts(t, "tmpfs")
	o2.Perm.Share = []string{"network"} // 即使 share network，后端仍隔离
	o2.Perm.NetBackend = "pasta"
	a2, err := Args(o2)
	if err != nil {
		t.Fatal(err)
	}
	if !argHas(a2, "--unshare-net") {
		t.Fatalf("网络后端应强制 --unshare-net")
	}
}
