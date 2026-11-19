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
// 返回 flagSet 之外的剩余参数（-- 之后的命令行）。
func flagPerm(args []string) (*perm.Permissions, []string, bool, bool, error) {
	p := &perm.Permissions{}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var share, socket, device, allow, fsSpecs, dbus, env, syscalls strSlice
	fs.StringVar(&p.App, "app", "", "应用名")
	fs.StringVar(&p.Home, "home", "", "自定义沙箱 HOME 目录")
	fs.Var(&share, "share", "共享: network,ipc")
	fs.Var(&socket, "socket", "socket: x11,wayland,pulseaudio,pipewire,cups,pcsc,ssh-agent")
	fs.Var(&device, "device", "设备: dri,kvm,all")
	fs.Var(&allow, "allow", "特性: devel,multiarch")
	fs.Var(&fsSpecs, "fs", "文件系统: rw:/path 或 ro:/path")
	fs.Var(&dbus, "dbus", "D-Bus: session.talk=NAME 等")
	fs.StringVar(&p.Seccomp, "seccomp", "", "过滤等级: low|medium|high")
	fs.Var(&syscalls, "allow-syscall", "追加白名单 syscall")
	fs.Var(&env, "env", "环境变量 KEY=VALUE")
	persist := fs.Bool("persist", false, "保存授权为应用配置")
	dry := fs.Bool("dry-run", false, "只打印 bwrap 命令行")
	if err := fs.Parse(args); err != nil {
		return nil, nil, false, false, err
	}
	p.Share, p.Socket, p.Device, p.Allow = share, socket, device, allow
	p.FS, p.DBus, p.Env, p.AllowSyscalls = fsSpecs, dbus, env, syscalls
	return p, fs.Args(), *persist, *dry, nil
}

// mergeFlags 把 FLAG 值覆盖到配置合并结果上（FLAG 非空才覆盖）。
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
	if len(f.Share) > 0 {
		m.Share = f.Share
	}
	if len(f.Socket) > 0 {
		m.Socket = f.Socket
	}
	if len(f.Device) > 0 {
		m.Device = f.Device
	}
	if len(f.Allow) > 0 {
		m.Allow = f.Allow
	}
	if len(f.FS) > 0 {
		m.FS = f.FS
	}
	if len(f.DBus) > 0 {
		m.DBus = f.DBus
	}
	if len(f.Env) > 0 {
		m.Env = f.Env
	}
	if len(f.AllowSyscalls) > 0 {
		m.AllowSyscalls = append(m.AllowSyscalls, f.AllowSyscalls...)
	}
	return &m
}

func cmdRun(argv []string) int {
	flags, rest, persist, dry, err := flagPerm(argv)
	if err != nil {
		return 2
	}
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "错误: 需要 -- 待执行命令，例如: cwrap run --app demo -- /bin/echo hi")
		return 2
	}

	// 配置合并：全局 < 应用 < FLAG
	global, _ := config.LoadGlobal()
	if flags.App != "" {
		appCfg, _ := config.LoadApp(flags.App)
		global.Overlay(appCfg)
	}
	merged := global
	merged = mergeFlags(merged, flags)
	merged.Seccomp = perm.DefaultSeccomp(merged.Seccomp)

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
	if merged.App == "" {
		fmt.Fprintln(os.Stderr, "错误: 必须通过 --app 或配置文件提供应用名")
		return 2
	}

	if persist {
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
		flags, restPos, _, _, err := flagPerm(rest)
		if err != nil {
			return 2
		}
		merged, _ := config.LoadGlobal()
		name := flags.App
		if name == "" && len(restPos) > 0 && !strings.HasPrefix(restPos[0], "-") {
			name = restPos[0]
		}
		if name == "" {
			// show 不带 app 时展示全局+FLAG
			merged = mergeFlags(merged, flags)
			merged.Seccomp = perm.DefaultSeccomp(merged.Seccomp)
			merged.App = "(未指定)"
		} else {
			appCfg, _ := config.LoadApp(name)
			merged.Overlay(appCfg)
			merged = mergeFlags(merged, flags)
			merged.Seccomp = perm.DefaultSeccomp(merged.Seccomp)
		}
		fmt.Print(merged.Describe())
		return 0
	case "export":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "用法: cwrap permission export APP [FLAGS...]")
			return 2
		}
		flags, _, _, _, err := flagPerm(rest)
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
		merged, _ := config.LoadGlobal()
		merged = mergeFlags(merged, flags)
		merged.Seccomp = perm.DefaultSeccomp(merged.Seccomp)
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
