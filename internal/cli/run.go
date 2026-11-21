package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"cwrap/internal/config"
	"cwrap/internal/daemon"
	"cwrap/internal/ipc"
	"cwrap/internal/perm"
)

// flagPerm 解析 run/permission 共用的权限 FLAG。
// 返回 -- 之后的剩余命令行、是否 --no-global。
func flagPerm(args []string) (*perm.Permissions, []string, bool, bool, bool, error) {
	p := &perm.Permissions{}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var share, socket, device, allow, fsSpecs, dbus, env, syscalls strSlice
	var noShare, noSocket, noDevice, noAllow, noFS, noDBus, noEnv strSlice
	var harden, unsetEnv, rawBwrap, rawDBus strSlice
	var netArgs strSlice
	fs.StringVar(&p.App, "app", "", "应用名（可省略，省略时 HOME 默认 $HOME/.var/sandbox/home）")
	fs.StringVar(&p.Home, "home", "", "自定义沙箱 HOME 目录")
	fs.Var(&share, "share", "共享: network,ipc")
	fs.Var(&socket, "socket", "socket: x11,wayland,pulseaudio,pipewire,cups,pcsc,ssh-agent,session-bus,system-bus,gpg-agent")
	fs.Var(&device, "device", "设备: dri,kvm,all,input,v4l,ntsync")
	fs.Var(&allow, "allow", "特性: devel,multiarch,portal")
	fs.Var(&fsSpecs, "fs", "文件系统: rw:/path 或 ro:/path（支持 flatpak 关键字，详见 docs/permissions.md）")
	fs.StringVar(&p.Tmp, "tmp", "", "/tmp 处理: tmpfs(默认)|host")
	fs.Var(&dbus, "dbus", "D-Bus: session.talk=NAME / session.see / session.call=NAME=iface.*@path / preset:notify,systray,gamemode,mpris=GLOB,portal,gnome-toolkit,ibus,fcitx")
	fs.StringVar(&p.Seccomp, "seccomp", "", "过滤等级: low|medium|high")
	fs.Var(&syscalls, "allow-syscall", "追加白名单 syscall")
	fs.Var(&env, "env", "环境变量 KEY=VALUE")
	// 否决（对齐 flatpak override）
	fs.Var(&noShare, "no-share", "否决已授予的 share 值")
	fs.Var(&noSocket, "no-socket", "否决已授予的 socket 值")
	fs.Var(&noDevice, "no-device", "否决已授予的 device 值")
	fs.Var(&noAllow, "no-allow", "否决已授予的 allow 值")
	fs.Var(&noFS, "no-fs", "否决已授予的 fs 项（按 ro:/path 原文精确匹配）")
	fs.Var(&noDBus, "no-dbus", "否决已授予的 dbus 规则/预设")
	fs.Var(&noEnv, "no-env", "否决已授予的 env 项")
	// bubblejail 对齐扩展
	fs.Var(&harden, "harden", "加固: namespaces（递归封死沙箱内建 namespace）,sync（屏蔽落盘 syscall）")
	fs.StringVar(&p.NetBackend, "net-backend", "", "网络后端: host(默认)|pasta|slirp4netns")
	fs.Var(&netArgs, "net-arg", "网络后端附加参数")
	fs.Var(&unsetEnv, "unset-env", "移除环境变量")
	fs.Var(&rawBwrap, "bwrap-arg", "原样透传 bwrap 参数（调试）")
	fs.Var(&rawDBus, "dbus-arg", "原样透传 xdg-dbus-proxy 参数（调试）")
	noGlobal := fs.Bool("no-global", false, "跳过全局配置合并（global.toml）")
	persist := fs.Bool("persist", false, "保存授权为应用配置")
	dry := fs.Bool("dry-run", false, "只打印 bwrap 命令行")
	if err := fs.Parse(args); err != nil {
		return nil, nil, false, false, false, err
	}
	deny := func(list strSlice) strSlice {
		out := strSlice{}
		for _, v := range list {
			out = append(out, "!"+v)
		}
		return out
	}
	p.Share = append(share, deny(noShare)...)
	p.Socket = append(socket, deny(noSocket)...)
	p.Device = append(device, deny(noDevice)...)
	p.Allow = append(allow, deny(noAllow)...)
	p.FS = append(fsSpecs, deny(noFS)...)
	p.DBus = append(dbus, deny(noDBus)...)
	p.Env = append(env, deny(noEnv)...)
	p.AllowSyscalls = syscalls
	p.Harden = harden
	p.NetBackendArgs = netArgs
	p.UnsetEnv = unsetEnv
	p.RawBwrap = rawBwrap
	p.RawDBus = rawDBus
	return p, fs.Args(), *noGlobal, *persist, *dry, nil
}

// mergeFlags 把 FLAG 值合并到配置合并结果上：
// 标量字段非空覆盖；列表字段累加并去除完全重复的值。
func mergeFlags(base *perm.Permissions, f *perm.Permissions) *perm.Permissions {
	m := *base
	if f.App != "" {
		m.App = f.App
	}
	if f.Home != "" {
		m.Home = f.Home
	}
	if f.Seccomp != "" {
		m.Seccomp = f.Seccomp
	}
	if f.Tmp != "" {
		m.Tmp = f.Tmp
	}
	m.Share = perm.OverlayList(m.Share, f.Share)
	m.Socket = perm.OverlayList(m.Socket, f.Socket)
	m.Device = perm.OverlayList(m.Device, f.Device)
	m.Allow = perm.OverlayList(m.Allow, f.Allow)
	m.FS = perm.OverlayList(m.FS, f.FS)
	m.DBus = perm.OverlayList(m.DBus, f.DBus)
	m.Env = perm.OverlayList(m.Env, f.Env)
	m.AllowSyscalls = perm.OverlayList(m.AllowSyscalls, f.AllowSyscalls)
	m.Harden = perm.OverlayList(m.Harden, f.Harden)
	m.NetBackendArgs = perm.OverlayList(m.NetBackendArgs, f.NetBackendArgs)
	m.UnsetEnv = perm.OverlayList(m.UnsetEnv, f.UnsetEnv)
	m.RawBwrap = perm.OverlayList(m.RawBwrap, f.RawBwrap)
	m.RawDBus = perm.OverlayList(m.RawDBus, f.RawDBus)
	if f.NetBackend != "" {
		m.NetBackend = f.NetBackend
	}
	m.ApplyDenies()
	return &m
}

func cmdRun(argv []string) int {
	flags, rest, noGlobal, persist, dry, err := flagPerm(argv)
	if err != nil {
		return 2
	}
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "错误: 需要 -- 待执行命令，例如: cwrap run --app demo -- /bin/echo hi")
		return 2
	}

	// 配置合并：全局 < 应用 < FLAG（--no-global 跳过全局配置）
	merged := &perm.Permissions{}
	if !noGlobal {
		global, _ := config.LoadGlobal()
		merged = global
	}
	if flags.App != "" {
		appCfg, _ := config.LoadApp(flags.App)
		merged.Overlay(appCfg)
	}
	merged = mergeFlags(merged, flags)
	merged.Seccomp = perm.DefaultSeccomp(merged.Seccomp)
	if merged.Tmp == "" {
		merged.Tmp = perm.DefaultTmp()
	}

	// --fs 与 --tmp 提供的 /tmp 冲突去重：过滤并警告，引导使用 --tmp
	filteredFS, tmpWarnings := perm.FilterTmpFSConflicts(merged)
	if len(tmpWarnings) > 0 {
		for _, w := range tmpWarnings {
			fmt.Fprintln(os.Stderr, w)
		}
		merged.FS = filteredFS
	}

	// 解析双横线后的可执行文件（宿主 PATH），并做权限校验
	cmdPath, err := resolveCmd(rest[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 2
	}
	if err := merged.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "权限错误:", err)
		return 2
	}

	if persist {
		if merged.App == "" {
			fmt.Fprintln(os.Stderr, "错误: --persist 需要应用名（--app 或配置文件）")
			return 2
		}
		if err := config.SaveApp(merged); err != nil {
			fmt.Fprintln(os.Stderr, "保存配置失败:", err)
			return 1
		}
		fmt.Printf("授权已保存到 %s\n", config.AppPath(merged.App))
	}

	if dry {
		spec := *merged
		b, _ := json.MarshalIndent(map[string]any{"argv": append([]string{cmdPath}, rest[1:]...), "spec": spec}, "", "  ")
		fmt.Println(string(b))
		return 0
	}

	return runViaDaemon(merged, append([]string{cmdPath}, rest[1:]...))
}

// resolveCmd 解析可执行文件绝对路径。
func resolveCmd(name string) (string, error) {
	if strings.ContainsRune(name, '/') {
		abs, err := filepath.Abs(name)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("可执行文件不存在: %s", name)
		}
		return abs, nil
	}
	// 宿主 PATH 查找（注意必须在沙箱外完成）
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		cand := filepath.Join(dir, name)
		if st, err := os.Stat(cand); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return cand, nil
		}
	}
	return "", fmt.Errorf("在宿主 PATH 中找不到命令: %s", name)
}

// runViaDaemon 连接 cwrapd 并执行一次沙箱运行。
func runViaDaemon(spec *perm.Permissions, argv []string) int {
	if err := daemon.EnsureRunning(); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	sock, _ := ipc.SocketPath()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "连接 cwrapd 失败:", err)
		return 1
	}
	defer conn.Close()
	uc := conn.(*net.UnixConn)

	// 1) 先传 stdio FD（协议要求第一个消息）
	fds := []int{int(os.Stdin.Fd()), int(os.Stdout.Fd()), int(os.Stderr.Fd())}
	if err := ipc.SendFDs(uc, fds); err != nil {
		fmt.Fprintln(os.Stderr, "发送 stdio FD 失败:", err)
		return 1
	}

	// 2) 发送请求
	req := ipc.Request{Cmd: "run", Spec: spec, Argv: argv}
	if err := ipc.WriteJSON(uc, req); err != nil {
		fmt.Fprintln(os.Stderr, "发送请求失败:", err)
		return 1
	}

	// 3) 信号转发 + tty 前台进程组管理
	tty := isTTY(os.Stdin)
	savedPgid := syscall.Getpgrp()
	sigCh := make(chan os.Signal, 8)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigCh {
			sig := s.(syscall.Signal)
			if ipc.WriteJSON(uc, ipc.SignalMsg{Cmd: "signal", Sig: int(sig)}) != nil {
				return // daemon 已失联，主循环会执行兜底
			}
		}
	}()

	// 4) 读取事件与最终应答
	br := bufio.NewReader(uc)
	sandboxPgid := 0 // 收到 started 事件后记录；>0 表示已知沙箱进程组
	for {
		var frame struct {
			Event    *string `json:"event"`
			PGID     int     `json:"pgid"`
			Ok       *bool   `json:"ok"`
			Error    string  `json:"error"`
			ExitCode int     `json:"exit_code"`
			Signal   int     `json:"signal"`
		}

		line, rerr := br.ReadBytes('\n')
		if rerr != nil {
			// daemon 失联（崩溃/被 kill/异常退出）：
			// 最终应答未到（还在循环内），由客户端兜底终止沙箱进程组
			if sandboxPgid > 0 {
				fmt.Fprintln(os.Stderr, "cwrapd 失联，终止沙箱进程组", sandboxPgid)
				syscall.Kill(-sandboxPgid, syscall.SIGTERM)
				// 宽限 3 秒后强制杀，避免卡死终端
				deadline := time.Now().Add(3 * time.Second)
				for time.Now().Before(deadline) {
					if syscall.Kill(-sandboxPgid, 0) != nil {
						break // 进程组已退出
					}
					time.Sleep(50 * time.Millisecond)
				}
				syscall.Kill(-sandboxPgid, syscall.SIGKILL)
			} else {
				fmt.Fprintln(os.Stderr, "cwrapd 连接中断")
			}
			restoreForeground(savedPgid)
			return 255
		}
		if jerr := json.Unmarshal(trimJSON(line), &frame); jerr != nil {
			continue
		}
		if frame.Event != nil && *frame.Event == "started" {
			// 无论是否 tty 都记录 pgid：失联兜底不依赖 tty
			sandboxPgid = frame.PGID
			if tty && frame.PGID > 0 {
				// 把终端前台进程组交给沙箱子进程组，交互程序才能正常读 tty
				setForegroundPGID(frame.PGID)
			}
		}
		if frame.Ok != nil {
			restoreForeground(savedPgid)
			if frame.Error != "" {
				fmt.Fprintln(os.Stderr, "错误:", frame.Error)
				return 255
			}
			// 新版 daemon：进程被信号终止 → 按 shell 惯例 128+sig
			if frame.Signal != 0 {
				fmt.Fprintf(os.Stderr, "cwrap: 进程被信号 %d 终止\n", frame.Signal)
				return 128 + frame.Signal
			}
			// 旧版 daemon 兼容：被信号终止的 ExitCode 是误导性的 -1
			if frame.ExitCode < 0 {
				fmt.Fprintln(os.Stderr, "cwrap: 进程异常终止")
				return 255
			}
			return frame.ExitCode
		}

	}

}

func trimJSON(line []byte) []byte {
	return []byte(strings.TrimSpace(string(line)))
}

func isTTY(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

func setForegroundPGID(pgid int) {
	fd := int(os.Stdin.Fd())
	unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, pgid)
}

func restoreForeground(pgid int) {
	if pgid > 0 {
		setForegroundPGID(pgid)
	}
}

// ---- permission 子命令 ----

func cmdPermission(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "用法: cwrap permission show|export [APP] [FLAGS...]")
		return 2
	}
	sub, rest := argv[0], argv[1:]
	switch sub {
	case "show":
		flags, restPos, noGlobal, _, _, err := flagPerm(rest)
		if err != nil {
			return 2
		}
		merged := &perm.Permissions{}
		if !noGlobal {
			merged, _ = config.LoadGlobal()
		}
		name := flags.App
		if name == "" && len(restPos) > 0 && !strings.HasPrefix(restPos[0], "-") {
			name = restPos[0]
		}
		if name == "" {
			// show 不带 app 时展示（全局+）FLAG
			merged = mergeFlags(merged, flags)
			merged.Seccomp = perm.DefaultSeccomp(merged.Seccomp)
			if merged.Tmp == "" {
				merged.Tmp = perm.DefaultTmp()
			}
			merged.App = "(未指定)"
		} else {
			appCfg, _ := config.LoadApp(name)
			merged.Overlay(appCfg)
			merged = mergeFlags(merged, flags)
			merged.Seccomp = perm.DefaultSeccomp(merged.Seccomp)
			if merged.Tmp == "" {
				merged.Tmp = perm.DefaultTmp()
			}
		}
		fmt.Print(merged.Describe())
		return 0
	case "export":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "用法: cwrap permission export APP [FLAGS...]")
			return 2
		}
		flags, _, noGlobal, _, _, err := flagPerm(rest)
		if err != nil {
			return 2
		}
		name := flags.App
		if name == "" && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			name = rest[0]
		}
		if name == "" {
			fmt.Fprintln(os.Stderr, "错误: 需要 APP 名或 --app FLAG")
			return 2
		}
		flags.App = name
		merged := &perm.Permissions{}
		if !noGlobal {
			merged, _ = config.LoadGlobal()
		}
		merged = mergeFlags(merged, flags)
		merged.Seccomp = perm.DefaultSeccomp(merged.Seccomp)
		if merged.Tmp == "" {
			merged.Tmp = perm.DefaultTmp()
		}
		if err := merged.Validate(); err != nil {
			fmt.Fprintln(os.Stderr, "权限错误:", err)
			return 2
		}
		if err := config.SaveApp(merged); err != nil {
			fmt.Fprintln(os.Stderr, "保存失败:", err)
			return 1
		}
		fmt.Printf("已写入 %s\n", config.AppPath(name))
		return 0
	default:
		fmt.Fprintf(os.Stderr, "未知子命令 permission %s\n", sub)
		return 2
	}
}

// ---- ps / kill / clean ----

func cmdPS() int {
	resp, err := simpleRequest(ipc.Request{Cmd: "ps"})
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	if len(resp.Runs) == 0 {
		fmt.Println("当前没有运行中的沙箱")
		return 0
	}
	fmt.Printf("%-20s %s\n", "ID", "APP")
	for _, r := range resp.Runs {
		fmt.Printf("%-20s %s\n", r.ID, r.App)
	}
	return 0
}

func cmdKill(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "用法: cwrap kill <ID|APP>")
		return 2
	}
	resp, err := simpleRequest(ipc.Request{Cmd: "kill", Target: args[0]})
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	if !resp.Ok {
		fmt.Fprintln(os.Stderr, "错误:", resp.Error)
		return 1
	}
	fmt.Println("已发送终止信号")
	return 0
}

func cmdClean() int {
	base := filepath.Join(runtimeDirForClean(), "cwrap")
	entries, err := os.ReadDir(base)
	if err != nil {
		fmt.Println("无需清理")
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pidFile := filepath.Join(base, e.Name(), ".pid")
		data, err := os.ReadFile(pidFile)
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err == nil && syscall.Kill(pid, 0) == nil {
			continue // daemon 仍存活
		}
		os.RemoveAll(filepath.Join(base, e.Name()))
		n++
	}
	fmt.Printf("清理了 %d 个陈旧目录\n", n)
	return 0
}

func runtimeDirForClean() string {
	if v := os.Getenv("XDG_RUNTIME_DIR"); v != "" {
		return v
	}
	return "/run/user/" + strconv.Itoa(syscall.Getuid())
}

// simpleRequest 发送 ps/kill 请求（同样按协议先传 3 个 FD）。
func simpleRequest(req ipc.Request) (ipc.Response, error) {
	if err := daemon.EnsureRunning(); err != nil {
		return ipc.Response{}, err
	}
	sock, _ := ipc.SocketPath()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return ipc.Response{}, err
	}
	defer conn.Close()
	uc := conn.(*net.UnixConn)
	nulls := []int{devNullFD(), devNullFD(), devNullFD()}
	if err := ipc.SendFDs(uc, nulls); err != nil {
		return ipc.Response{}, err
	}
	if err := ipc.WriteJSON(uc, req); err != nil {
		return ipc.Response{}, err
	}
	var resp ipc.Response
	if err := ipc.ReadJSON(bufio.NewReader(uc), &resp); err != nil {
		return ipc.Response{}, err
	}
	return resp, nil
}

func devNullFD() int {
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return -1
	}
	return int(f.Fd())
}
