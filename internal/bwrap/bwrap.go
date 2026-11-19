// Package bwrap 负责把权限模型翻译成 bubblewrap 参数。
//
// 基线：最小 rootfs（tmpfs 根 + 只读 /usr、/etc），HOME 始终隔离，
// 双横线后的可执行文件若不在已挂载范围内则自动只读挂入。
package bwrap

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cwrap/internal/perm"
)

// Options 描述一次 bwrap 参数拼装所需的全部输入。
type Options struct {
	Perm      *perm.Permissions
	UID       int
	HomeDir   string // 宿主侧沙箱 HOME 目录
	SeccompFD int    // 传给 bwrap 的 BPF fd 号（0 表示不启用）
	TmpDir    string // sandbox /tmp 模式：daemon 预创建的宿主侧私有目录（bind 模式由 daemon 填用户路径）

	CmdPath string   // 双横线后解析出的可执行文件（宿主路径）
	CmdArgs []string // 其余参数

	DBusSessionPath string // 宿主侧 xdg-dbus-proxy 会话 socket 路径（空 = 无）
	DBusSystemPath  string // 宿主侧系统 socket 路径（空 = 无）
}

// Args 生成完整 bwrap 参数（不含 bwrap 自身路径）。
func Args(o *Options) ([]string, error) {
	p := o.Perm
	uid := o.UID
	a := []string{
		"--die-with-parent",
		"--cap-drop", "ALL",
		"--unshare-user",
		"--unshare-pid",
		"--unshare-uts",
		"--unshare-cgroup",
		"--clearenv",
	}

	// /tmp 处理方式（默认 sandbox：私有目录，daemon 退出时清理）
	ts, err := perm.ParseTmp(p.Tmp)
	if err != nil {
		return nil, err
	}

	// seccomp（fd 由调用方通过 ExtraFiles 传入）
	if o.SeccompFD > 0 {
		a = append(a, "--seccomp", fmt.Sprint(o.SeccompFD))
	}

	// 共享：默认全部隔离，仅显式授权时与宿主共享
	if !p.ShareIPC() {
		a = append(a, "--unshare-ipc")
	}
	if !p.ShareNet() {
		a = append(a, "--unshare-net")
	}

	// 基础系统目录（只读）
	a = append(a, "--ro-bind", "/usr", "/usr")
	a = append(a, rootSymlinks()...)
	a = append(a, "--ro-bind-try", "/etc", "/etc")
	a = append(a, "--proc", "/proc")
	a = append(a, "--tmpfs", "/run")

	// /tmp：sandbox（私有目录）| tmpfs（全空）| host（宿主）| bind（用户指定目录）
	switch ts.Kind {
	case "tmpfs":
		a = append(a, "--tmpfs", "/tmp")
	case "host":
		a = append(a, "--bind", "/tmp", "/tmp")
	case "bind":
		a = append(a, "--bind", ts.Path, "/tmp")
	default: // sandbox：daemon 已创建私有目录
		if o.TmpDir == "" {
			return nil, fmt.Errorf("tmp=sandbox 需要 daemon 提供私有 tmp 目录（TmpDir 为空）")
		}
		a = append(a, "--bind", o.TmpDir, "/tmp")
	}
	hostTmpExposed := ts.Kind == "host" || (ts.Kind == "bind" && ts.Path == "/tmp")

	// /dev
	if perm.Has(p.Device, "all") {
		a = append(a, "--dev-bind", "/dev", "/dev")
	} else {
		a = append(a, "--dev", "/dev")
		if perm.Has(p.Device, "dri") {
			a = append(a, "--dev-bind-try", "/dev/dri", "/dev/dri")
			a = append(a, "--ro-bind-try", "/sys/dev/char", "/sys/dev/char")
			a = append(a, "--ro-bind-try", "/sys/devices", "/sys/devices")
		}
		if perm.Has(p.Device, "kvm") {
			a = append(a, "--dev-bind-try", "/dev/kvm", "/dev/kvm")
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
	a = append(a, "--dir", fmt.Sprintf("/run/user/%d", uid))

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
	}
	if perm.Has(p.Socket, "wayland") {
		if wd := os.Getenv("WAYLAND_DISPLAY"); wd != "" {
			if filepath.IsAbs(wd) {
				a = append(a, "--ro-bind-try", wd, wd)
			} else {
				host := filepath.Join(xdgRuntimeDir(uid), wd)
				a = append(a, "--ro-bind-try", host, filepath.Join("/run/user", fmt.Sprint(uid), wd))
			}
			sockEnv["WAYLAND_DISPLAY"] = wd
		}
	}
	if perm.Has(p.Socket, "pulseaudio") {
		rt := xdgRuntimeDir(uid)
		a = append(a, "--ro-bind-try", filepath.Join(rt, "pulse"), filepath.Join("/run/user", fmt.Sprint(uid), "pulse"))
		sockEnv["PULSE_SERVER"] = fmt.Sprintf("unix:/run/user/%d/pulse/native", uid)
	}
	if perm.Has(p.Socket, "pipewire") {
		rt := xdgRuntimeDir(uid)
		for _, name := range []string{"pipewire-0", "pipewire-0.lock", "pipewire-0.manager"} {
			a = append(a, "--ro-bind-try", filepath.Join(rt, name), filepath.Join("/run/user", fmt.Sprint(uid), name))
		}
	}
	if perm.Has(p.Socket, "cups") {
		rt := xdgRuntimeDir(uid)
		a = append(a, "--ro-bind-try", filepath.Join(rt, "cups"), filepath.Join("/run/user", fmt.Sprint(uid), "cups"))
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

	// D-Bus 代理 socket 挂载
	if o.DBusSessionPath != "" {
		a = append(a, "--dir", "/run/cwrap")
		a = append(a, "--ro-bind", o.DBusSessionPath, "/run/cwrap/sessionBus")
		sockEnv["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/run/cwrap/sessionBus"
	}
	if o.DBusSystemPath != "" {
		a = append(a, "--dir", "/run/cwrap")
		a = append(a, "--ro-bind", o.DBusSystemPath, "/run/cwrap/systemBus")
		sockEnv["DBUS_SYSTEM_BUS_ADDRESS"] = "unix:path=/run/cwrap/systemBus"
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

	// 环境变量
	a = append(a, "--setenv", "PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
	for _, k := range []string{"TERM", "LANG", "LC_ALL", "USER", "LOGNAME"} {
		if v := os.Getenv(k); v != "" {
			a = append(a, "--setenv", k, v)
		}
	}
	a = append(a, "--setenv", "HOME", homeMount)
	a = append(a, "--setenv", "XDG_RUNTIME_DIR", fmt.Sprintf("/run/user/%d", uid))
	for k, v := range sockEnv {
		a = append(a, "--setenv", k, v)
	}
	for _, e := range p.Env {
		k, v, ok := strings.Cut(e, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("非法 --env 项 %q（应为 KEY=VALUE）", e)
		}
		a = append(a, "--setenv", k, v)
	}

	// 双横线后的可执行文件自动挂载
	mounts, err := AutoMountArgs(o.CmdPath, homeMount, extraRoots)
	if err != nil {
		return nil, err
	}
	a = append(a, mounts...)

	a = append(a, "--", o.CmdPath)
	a = append(a, o.CmdArgs...)
	return a, nil
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
