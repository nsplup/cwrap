// Package bwrap 负责把权限模型翻译成 bubblewrap 参数。
//
// 基线：最小 rootfs（tmpfs 根 + 只读 /usr、/etc），HOME 始终隔离，
// 双横线后的可执行文件若不在已挂载范围内则自动只读挂入。
// socket/设备生成细节对齐 Flatpak 与 bubblejail（见 docs/permissions.md
// 的三栏对照矩阵）。
package bwrap

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"cwrap/internal/perm"
)

// Options 描述一次 bwrap 参数拼装所需的全部输入。
type Options struct {
	Perm      *perm.Permissions
	UID       int
	HomeDir   string // 宿主侧沙箱 HOME 目录
	SeccompFD int    // 传给 bwrap 的 BPF fd 号（0 表示不启用）

	CmdPath string   // 双横线后解析出的可执行文件（宿主路径）
	CmdArgs []string // 其余参数

	DBusSessionPath string // 宿主侧 xdg-dbus-proxy 会话 socket 路径（空 = 无）
	DBusSystemPath  string // 宿主侧系统 socket 路径（空 = 无）

	FlatpakInfoFD int // memfd 伪 /.flatpak-info（--allow portal；0 = 不传）
	InfoFD        int // --info-fd（网络后端需要沙箱 PID；0 = 不传）
	NetResolvFD   int // memfd DNS 配置（slirp4netns/pasta 后端；0 = 不传）
}

// Args 生成完整 bwrap 参数（不含 bwrap 自身路径）。
func Args(o *Options) ([]string, error) {
	p := o.Perm
	uid := o.UID
	a := []string{
		"--die-with-parent",
		"--unshare-user",
		"--unshare-pid",
		"--unshare-uts",
		"--unshare-cgroup",
		"--clearenv",
	}

	// --harden namespaces（对齐 bubblejail namespaces_limits）：pid1 需要
	// 在自身 userns 内写 /proc/sys/user/max_*_namespaces，不能 cap-drop ALL。
	// 这是文档声明的安全权衡（capability 换递归 namespace 封锁）。
	hardenNS := perm.Has(p.Harden, "namespaces")
	if !hardenNS {
		a = append(a, "--cap-drop", "ALL")
	}

	// /tmp 处理方式（默认 tmpfs：全空临时目录）
	ts, err := perm.ParseTmp(p.Tmp)
	if err != nil {
		return nil, err
	}

	// seccomp（fd 由调用方通过 ExtraFiles 传入）
	if o.SeccompFD > 0 {
		a = append(a, "--seccomp", fmt.Sprint(o.SeccompFD))
	}

	// 网络后端（对齐 bubblejail pasta_network/slirp4netns 服务）：
	// 非 host 后端一律独立 netns，由 daemon 在沙箱就绪后挂接。
	backend := p.UserNetBackend()
	shareNet := perm.Has(p.Share, "network") && backend == "host"

	// 共享：默认全部隔离，仅显式授权时与宿主共享
	if !perm.Has(p.Share, "ipc") {
		a = append(a, "--unshare-ipc")
	}
	if !shareNet {
		a = append(a, "--unshare-net")
	}

	// 网络后端需要 --info-fd 取沙箱 PID（daemon 用它挂接 pasta/slirp4netns）
	if o.InfoFD > 0 {
		a = append(a, "--info-fd", strconv.Itoa(o.InfoFD))
	}

	// 基础系统目录（只读）
	a = append(a, "--ro-bind", "/usr", "/usr")
	a = append(a, rootSymlinks()...)
	a = append(a, "--ro-bind-try", "/etc", "/etc")
	// 网络后端（slirp4netns/pasta）注入 DNS（10.0.2.3，覆盖宿主 resolv.conf）
	if o.NetResolvFD > 0 {
		a = append(a, "--ro-bind-data", strconv.Itoa(o.NetResolvFD), "/etc/resolv.conf")
	}
	a = append(a, "--proc", "/proc")
	a = append(a, "--tmpfs", "/run")

	// /tmp：tmpfs（全空，默认）| host（宿主）
	switch ts.Kind {
	case "host":
		a = append(a, "--bind", "/tmp", "/tmp")
	default: // tmpfs
		a = append(a, "--tmpfs", "/tmp")
	}
	hostTmpExposed := ts.Kind == "host"

	// /sys 基线（对齐 bubblejail 默认服务）：私有 /sys 目录 + CPU 信息只读
	// （JIT/游戏/lscpu 等普遍依赖 /sys/devices/system/cpu）。
	// 注意：bwrap 的 --perms 必须紧跟 --dir/--tmpfs/--symlink 等"创建"类
	// 选项，不能挂在 --ro-bind-try 前面（目标目录由 bwrap 自动创建）。
	a = append(a, "--perms", "0700", "--dir", "/sys")
	a = append(a, "--ro-bind-try", "/sys/devices/system/cpu", "/sys/devices/system/cpu")

	// /dev
	if perm.Has(p.Device, "all") {
		a = append(a, "--dev-bind", "/dev", "/dev")
	} else {
		a = append(a, "--dev", "/dev")
		if perm.Has(p.Device, "dri") {
			a = append(a, driArgs()...)
		}
		if perm.Has(p.Device, "kvm") {
			a = append(a, "--dev-bind-try", "/dev/kvm", "/dev/kvm")
		}
		if perm.Has(p.Device, "input") {
			a = append(a, inputArgs()...)
		}
		if perm.Has(p.Device, "v4l") {
			a = append(a, v4lArgs()...)
		}
		if perm.Has(p.Device, "ntsync") {
			a = append(a, "--dev-bind-try", "/dev/ntsync", "/dev/ntsync")
		}
	}

	// X11 / Wayland / PulseAudio 需要的共享内存
	if perm.Has(p.Socket, "x11") || perm.Has(p.Socket, "wayland") || perm.Has(p.Socket, "pulseaudio") {
		a = append(a, "--tmpfs", "/dev/shm")
	}

	// 沙箱 HOME：始终隔离
	if err := os.MkdirAll(o.HomeDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建沙箱 HOME 目录 %s: %w", o.HomeDir, err)
	}
	homeMount := o.HomeDir // 沙箱内挂载在与宿主相同的绝对路径
	parent := filepath.Dir(homeMount)
	if parent != "/" && parent != homeMount {
		a = append(a, "--dir", parent)
	}
	a = append(a, "--bind", o.HomeDir, homeMount)
	a = append(a, "--chdir", homeMount)

	// 用户运行时目录基座
	rtIn := fmt.Sprintf("/run/user/%d", uid)
	a = append(a, "--dir", rtIn)

	// socket 授权
	sockEnv := map[string]string{}
	if perm.Has(p.Socket, "x11") {
		// host /tmp 已整体 bind 时 .X11-unix 已随 /tmp 可见，无需重复挂载
		// （flatpak 同样如此；代价是该 socket 随 /tmp 变为可写）
		if !hostTmpExposed {
			a = append(a, "--ro-bind-try", "/tmp/.X11-unix", "/tmp/.X11-unix")
		}
		if v := os.Getenv("DISPLAY"); v != "" {
			sockEnv["DISPLAY"] = v
		}
		// XAUTHORITY 写路径隔离（对齐 bubblejail x11 服务）：
		// 只读挂到 /tmp/.Xauthority 并改写环境变量，应用无法改写真实 xauth
		if xa := os.Getenv("XAUTHORITY"); xa != "" {
			a = append(a, "--ro-bind-try", xa, "/tmp/.Xauthority")
			sockEnv["XAUTHORITY"] = "/tmp/.Xauthority"
		}
		// Xwayland 场景（bubblejail 同款处理）
		if _, ok := sockEnv["DISPLAY"]; ok {
			sockEnv["XDG_SESSION_TYPE"] = "x11"
		}
	}
	if perm.Has(p.Socket, "wayland") {
		if wd := os.Getenv("WAYLAND_DISPLAY"); wd != "" {
			// 宿主 socket 任意命名 → 沙箱内统一为 wayland-0
			// （对齐 bubblejail wayland 服务）
			var hostPath string
			if filepath.IsAbs(wd) {
				hostPath = wd
			} else {
				hostPath = filepath.Join(xdgRuntimeDir(uid), wd)
			}
			a = append(a, "--ro-bind-try", hostPath, filepath.Join(rtIn, "wayland-0"))
			sockEnv["WAYLAND_DISPLAY"] = "wayland-0"
			sockEnv["GDK_BACKEND"] = "wayland"
			sockEnv["QT_QPA_PLATFORM"] = "wayland"
			sockEnv["SDL_VIDEODRIVER"] = "wayland"
			if _, ok := sockEnv["XDG_SESSION_TYPE"]; !ok {
				sockEnv["XDG_SESSION_TYPE"] = "wayland"
			}
		}
	}
	if perm.Has(p.Socket, "pulseaudio") {
		// 对齐 bubblejail pulse_audio：只挂 native socket（rw，客户端可连）
		rt := xdgRuntimeDir(uid)
		a = append(a, "--dir", filepath.Join(rtIn, "pulse"))
		a = append(a, "--bind-try", filepath.Join(rt, "pulse", "native"), filepath.Join(rtIn, "pulse", "native"))
		sockEnv["PULSE_SERVER"] = fmt.Sprintf("unix:/run/user/%d/pulse/native", uid)
	}
	if perm.Has(p.Socket, "pipewire") {
		rt := xdgRuntimeDir(uid)
		for _, name := range []string{"pipewire-0", "pipewire-0.lock", "pipewire-0.manager"} {
			a = append(a, "--ro-bind-try", filepath.Join(rt, name), filepath.Join(rtIn, name))
		}
	}
	if perm.Has(p.Socket, "cups") {
		rt := xdgRuntimeDir(uid)
		a = append(a, "--ro-bind-try", filepath.Join(rt, "cups"), filepath.Join(rtIn, "cups"))
	}
	if perm.Has(p.Socket, "pcsc") {
		a = append(a, "--ro-bind-try", "/run/pcscd/pcscd.comm", "/run/pcscd/pcscd.comm")
	}
	if perm.Has(p.Socket, "ssh-agent") {
		if sa := os.Getenv("SSH_AUTH_SOCK"); sa != "" {
			a = append(a, "--ro-bind-try", sa, sa)
			sockEnv["SSH_AUTH_SOCK"] = sa
		}
	}
	if perm.Has(p.Socket, "gpg-agent") {
		// 对齐 flatpak --socket=gpg-agent：共享 agent socket 与 ~/.gnupg（只读）
		rt := xdgRuntimeDir(uid)
		a = append(a, "--dir", filepath.Join(rtIn, "gnupg"))
		a = append(a, "--bind-try", filepath.Join(rt, "gnupg"), filepath.Join(rtIn, "gnupg"))
		if gh, err := os.UserHomeDir(); err == nil {
			a = append(a, "--ro-bind-try", filepath.Join(gh, ".gnupg"), filepath.Join(homeMount, ".gnupg"))
		}
	}
	// 直通逃生门（对齐 flatpak --socket=session-bus/system-bus）：
	// 不经过 xdg-dbus-proxy 过滤，风险等同共享整条总线
	if perm.Has(p.Socket, "session-bus") {
		rt := xdgRuntimeDir(uid)
		a = append(a, "--bind-try", filepath.Join(rt, "bus"), filepath.Join(rtIn, "bus"))
		sockEnv["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + filepath.Join(rtIn, "bus")
		fmt.Fprintln(os.Stderr, "警告: --socket session-bus 为未过滤直通，沙箱内可调用宿主会话总线上的全部服务")
	}
	if perm.Has(p.Socket, "system-bus") {
		a = append(a, "--ro-bind-try", "/run/dbus/system_bus_socket", "/run/dbus/system_bus_socket")
		sockEnv["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/run/dbus/system_bus_socket"
		fmt.Fprintln(os.Stderr, "警告: --socket system-bus 为未过滤直通，沙箱内可调用宿主系统总线上的全部服务")
	}

	// D-Bus 代理 socket 挂载（proxy 优先于直通逃生门）
	if o.DBusSessionPath != "" {
		a = append(a, "--dir", "/run/cwrap")
		a = append(a, "--ro-bind", o.DBusSessionPath, "/run/cwrap/sessionBus")
		sockEnv["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/run/cwrap/sessionBus"
	} else if !perm.Has(p.Socket, "session-bus") {
		// 对齐 flatpak：未授予会话总线时显式设为 "disabled"——
		// GLib ≥2.80 会静默接受（配合 /.flatpak-info 的 flatpak 语义），
		// 避免 Chromium 等回退到 autolaunch 拉起 dbus-daemon。
		sockEnv["DBUS_SESSION_BUS_ADDRESS"] = "disabled"
	}
	if o.DBusSystemPath != "" {
		a = append(a, "--dir", "/run/cwrap")
		a = append(a, "--ro-bind", o.DBusSystemPath, "/run/cwrap/systemBus")
		sockEnv["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/run/cwrap/systemBus"
	}

	// portal 权限包（对齐 bubblejail xdg_desktop_portal 服务）
	if perm.Has(p.Allow, "portal") {
		if o.FlatpakInfoFD > 0 {
			a = append(a, "--ro-bind-data", strconv.Itoa(o.FlatpakInfoFD), "/.flatpak-info")
		}
		sockEnv["GTK_USE_PORTAL"] = "1"
		// flatpak-xdg-utils 提供的 xdg-open 走 portal OpenURI
		if _, err := os.Stat("/usr/lib/flatpak-xdg-utils/xdg-open"); err == nil {
			a = append(a, "--ro-bind-try", "/usr/lib/flatpak-xdg-utils/xdg-open", "/usr/bin/xdg-open")
		}
	}

	// 额外文件系统授权（PATH 支持 flatpak 关键字展开，可一对多）
	extraRoots := []string{}
	for _, fs := range p.FS {
		mode, rawPath, err := perm.ParseFS(fs)
		if err != nil {
			return nil, err
		}
		resolved, tryOK, err := perm.ResolveFSPath(rawPath)
		if err != nil {
			return nil, err
		}
		for _, path := range resolved {
			// host /tmp 已整体可见时跳过 /tmp 下的重复挂载
			// （CLI 层已过滤并警告，此处兜底去重）
			if hostTmpExposed && (path == "/tmp" || strings.HasPrefix(path, "/tmp/")) {
				continue
			}
			act := "--bind"
			if mode == "ro" {
				act = "--ro-bind"
			}
			if tryOK {
				act += "-try"
			}
			a = append(a, act, path, path)
			extraRoots = append(extraRoots, path)
		}
	}
	if hostTmpExposed {
		extraRoots = append(extraRoots, "/tmp") // 自动挂载判定：/tmp 下的可执行文件已被覆盖
	}

	// resolv.conf 断链修复（对齐 bubblejail network 服务）：share network 且
	// 宿主 /etc/resolv.conf 是指向 /run/systemd/resolve 的 symlink 时，
	// 沙箱内 /run 为空 tmpfs，symlink 断链导致解析失败 → 补挂 resolved 目录。
	if shareNet {
		if fi, err := os.Lstat("/etc/resolv.conf"); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			a = append(a, "--ro-bind-try", "/run/systemd/resolve", "/run/systemd/resolve")
		}
	}

	// 环境变量
	a = append(a, "--setenv", "PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
	for _, k := range []string{"TERM", "LANG", "LC_ALL", "USER", "LOGNAME"} {
		if v := os.Getenv(k); v != "" {
			a = append(a, "--setenv", k, v)
		}
	}
	a = append(a, "--setenv", "HOME", homeMount)
	a = append(a, "--setenv", "XDG_RUNTIME_DIR", rtIn)
	for k, v := range sockEnv {
		a = append(a, "--setenv", k, v)
	}
	// 输入法预设环境（对齐 bubblejail ibus/fcitx 服务）
	applyIMEnv(p, sockEnv)
	for _, e := range p.Env {
		k, v, ok := strings.Cut(e, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("非法 --env 项 %q（应为 KEY=VALUE）", e)
		}
		a = append(a, "--setenv", k, v)
	}
	// --unset-env（对齐 flatpak --unset-env；与 --clearenv 叠加时为幂等兼容语义）
	for _, k := range p.UnsetEnv {
		a = append(a, "--unset-env", k)
	}

	// 双横线后的可执行文件自动挂载
	mounts, err := AutoMountArgs(o.CmdPath, homeMount, extraRoots)
	if err != nil {
		return nil, err
	}
	a = append(a, mounts...)

	// 调试透传（对齐 bubblejail debug 服务 raw_bwrap_args）
	a = append(a, p.RawBwrap...)

	if hardenNS {
		// --harden namespaces（对齐 bubblejail namespaces_limits）：
		// pid1 先写零 /proc/sys/user/max_*_namespaces 再 exec 目标，
		// 递归封死沙箱内继续创建命名空间的逃逸路径。
		script := "for f in /proc/sys/user/max_*_namespaces; do echo 0 > \"$f\" 2>/dev/null; done; exec \"$@\""
		a = append(a, "--", "/bin/sh", "-c", script, "sh", o.CmdPath)
		a = append(a, o.CmdArgs...)
	} else {
		a = append(a, "--", o.CmdPath)
		a = append(a, o.CmdArgs...)
	}
	return a, nil
}

// applyIMEnv 注入输入法预设环境变量。
func applyIMEnv(p *perm.Permissions, sockEnv map[string]string) {
	presets := perm.UsedPresets(p.DBus)
	has := func(n string) bool { return inSlice(presets, n) }
	if has("ibus") {
		sockEnv["GTK_IM_MODULE"] = "ibus"
		sockEnv["QT_IM_MODULE"] = "ibus"
		sockEnv["XMODIFIERS"] = "@im=ibus"
		sockEnv["IBUS_USE_PORTAL"] = "1"
	}
	if has("fcitx") {
		sockEnv["GTK_IM_MODULE"] = "fcitx"
		sockEnv["QT_IM_MODULE"] = "fcitx"
		sockEnv["XMODIFIERS"] = "@im=fcitx"
		sockEnv["SDL_IM_MODULE"] = "fcitx"
		sockEnv["GLFW_IM_MODULE"] = "ibus"
	}
}

func inSlice(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// driArgs 生成 DRI/GPU 相关参数（对齐 bubblejail direct_rendering 服务：
// 设备节点 + sysfs 重建 + NVIDIA 分支）。
func driArgs() []string {
	var a []string
	a = append(a, "--dev-bind-try", "/dev/dri", "/dev/dri")
	a = append(a, "--ro-bind-try", "/sys/dev/char", "/sys/dev/char")
	a = append(a, "--ro-bind-try", "/sys/devices", "/sys/devices")
	// NVIDIA 设备节点与模块 sysfs
	for _, d := range globOrEmpty("/dev/nvidia*") {
		a = append(a, "--dev-bind-try", d, d)
	}
	for _, m := range globOrEmpty("/sys/module/nvidia*") {
		a = append(a, "--ro-bind-try", m, m)
	}
	// /sys/class/drm 重建：逐条镜像 symlink（目标为 /sys/devices 下的
	// 相对路径，随 sysfs 一起可用）
	if entries, err := os.ReadDir("/sys/class/drm"); err == nil {
		a = append(a, "--perms", "0755", "--dir", "/sys/class/drm")
		for _, e := range entries {
			tgt, err := os.Readlink(filepath.Join("/sys/class/drm", e.Name()))
			if err != nil || !filepath.IsAbs(tgt) && !isRelativeLink(tgt) {
				continue
			}
			a = append(a, "--symlink", tgt, filepath.Join("/sys/class/drm", e.Name()))
		}
	}
	return a
}

// inputArgs 生成手柄/输入设备参数（对齐 bubblejail joystick 服务）。
func inputArgs() []string {
	var a []string
	for _, d := range globOrEmpty("/dev/input/js*") {
		a = append(a, "--dev-bind-try", d, d)
	}
	for _, d := range globOrEmpty("/dev/input/event*") {
		a = append(a, "--dev-bind-try", d, d)
	}
	a = append(a, "--ro-bind-try", "/sys/devices", "/sys/devices")
	if entries, err := os.ReadDir("/sys/class/input"); err == nil {
		a = append(a, "--perms", "0755", "--dir", "/sys/class/input")
		for _, e := range entries {
			if tgt, err := os.Readlink(filepath.Join("/sys/class/input", e.Name())); err == nil {
				a = append(a, "--symlink", tgt, filepath.Join("/sys/class/input", e.Name()))
			}
		}
	}
	return a
}

// v4lArgs 生成摄像头/采集卡参数（对齐 bubblejail v4l 服务）。
func v4lArgs() []string {
	var a []string
	for _, d := range globOrEmpty("/dev/video*") {
		a = append(a, "--dev-bind-try", d, d)
	}
	for _, d := range globOrEmpty("/dev/media*") {
		a = append(a, "--dev-bind-try", d, d)
	}
	a = append(a, "--ro-bind-try", "/sys/class/video4linux", "/sys/class/video4linux")
	a = append(a, "--ro-bind-try", "/sys/bus/media", "/sys/bus/media")
	a = append(a, "--ro-bind-try", "/sys/devices", "/sys/devices")
	return a
}

func globOrEmpty(pattern string) []string {
	m, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	sortStrings(m)
	return m
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func isRelativeLink(tgt string) bool {
	return strings.HasPrefix(tgt, ".") || strings.HasPrefix(tgt, "/")
}

// rootSymlinks 依据宿主形态生成 /bin /sbin /lib /lib64 的符号链接参数。
// merged-usr 宿主（/bin -> usr/bin）用 --symlink 指向 /usr 下对应目录；
// 传统宿主则直接只读挂载。
func rootSymlinks() []string {
	var a []string
	for _, name := range []string{"bin", "sbin", "lib", "lib64"} {
		host := filepath.Join("/", name)
		fi, err := os.Lstat(host)
		if err != nil {
			continue
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if tgt, err := os.Readlink(host); err == nil && strings.HasPrefix(tgt, "usr/") {
				a = append(a, "--symlink", tgt, host)
				continue
			}
		}
		if fi.IsDir() {
			a = append(a, "--ro-bind-try", host, host)
		}
	}
	return a
}

// AutoMountArgs 检查 cmdPath 是否落在已挂载范围内；
// 不在则将其（以及脚本解释器）以只读方式挂到沙箱内相同绝对路径。
func AutoMountArgs(cmdPath, homeMount string, extraRoots []string) ([]string, error) {
	mounts := []string{}
	real, err := filepath.EvalSymlinks(cmdPath)
	if err != nil {
		return nil, fmt.Errorf("解析可执行文件 %s: %w", cmdPath, err)
	}
	covered := func(p string) bool {
		for _, root := range append([]string{"/usr", "/etc", homeMount}, extraRoots...) {
			if root != "" && (p == root || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/")) {
				return true
			}
		}
		return false
	}
	need := []string{}
	if !covered(real) {
		need = append(need, real)
	}
	// 脚本解释器（仅一层 shebang 解析）
	if isScript(real) {
		interp, err := shebang(real)
		if err == nil && interp != "" {
			ir, err := filepath.EvalSymlinks(interp)
			if err == nil && !covered(ir) {
				need = append(need, ir)
			}
		}
	}
	for _, f := range need {
		parent := filepath.Dir(f)
		if parent != "/" {
			mounts = append(mounts, "--dir", parent)
		}
		mounts = append(mounts, "--ro-bind", f, f)
	}
	return mounts, nil
}

func isScript(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	r := bufio.NewReader(f)
	b0, _ := r.ReadByte()
	b1, _ := r.ReadByte()
	return b0 == '#' && b1 == '!'
}

func shebang(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return "", sc.Err()
	}
	line := strings.TrimPrefix(sc.Text(), "#!")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], nil
}

func xdgRuntimeDir(uid int) string {
	if v := os.Getenv("XDG_RUNTIME_DIR"); v != "" {
		return v
	}
	return fmt.Sprintf("/run/user/%d", uid)
}
