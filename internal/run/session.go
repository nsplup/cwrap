// Package run 在 cwrap 主进程内直接执行沙箱会话（无守护进程）。
//
// 生命周期：cwrap 持有一条 sync 管道的写端，读端经 bwrap --sync-fd
// 传给主沙箱与（portal 场景下）包装 D-Bus 代理的 bwrap。无论 cwrap
// 以何种方式退出（正常结束、panic、被 SIGKILL），写端都随进程关闭，
// bwrap 检测到 HUP 后立即终止对应沙箱——沙箱生命周期与主进程严格同步。
// 未包装的 xdg-dbus-proxy 由其 --fd 就绪管道承担同一语义（读端由
// cwrap 持有到运行结束，对端关闭即代理自停并 unlink socket）。
//
// 临时文件：socket 目录位于持久化的按配置目录内（见 instance.go），
// 正常退出注销并删除；异常残留由同配置下一次启动清扫。
package run

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"cwrap/internal/bwrap"
	"cwrap/internal/config"
	"cwrap/internal/dbusproxy"
	"cwrap/internal/perm"
	"cwrap/internal/seccomp"
)

// Session 执行一次完整的沙箱运行，返回进程退出码
// （被信号终止时按 shell 惯例返回 128+sig）。
func Session(spec *perm.Permissions, argv []string) int {
	if spec == nil || len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "错误: 缺少待执行命令")
		return 2
	}
	inst, err := Prepare(spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误: 准备实例目录失败:", err)
		return 1
	}
	defer inst.Release()
	return session(spec, argv, inst)
}

func session(spec *perm.Permissions, argv []string, inst *Instance) int {
	fail := func(format string, a ...any) int {
		fmt.Fprintf(os.Stderr, "错误: "+format+"\n", a...)
		return 1
	}

	// 生命周期 sync 管道：写端由本进程持有到运行结束（defer 关闭），
	// 读端经 --sync-fd 交给主沙箱 bwrap 与代理包装 bwrap。
	syncR, syncW, err := os.Pipe()
	if err != nil {
		return fail("创建 sync 管道: %v", err)
	}
	defer syncR.Close()
	defer syncW.Close()

	// 以下变量在 cleanup 闭包定义之前声明：闭包按引用捕获，
	// 赋值可以晚于闭包定义（Go 词法作用域规则）。
	var sessionProxy, systemProxy *dbusproxy.Proxy
	var seccompFile, bwrapInfoFile *os.File
	var extraFiles []*os.File
	var portalDir string

	cleanup := func() {
		sessionProxy.Stop()
		systemProxy.Stop()
		if seccompFile != nil {
			seccompFile.Close()
		}
		if bwrapInfoFile != nil {
			bwrapInfoFile.Close()
		}
		for _, f := range extraFiles {
			f.Close() // memfd/管道父进程侧副本；重复 Close 无害
		}
		if portalDir != "" {
			os.RemoveAll(portalDir)
		}
	}
	// 唯一清理出口：无论哪条路径返回（fail / 正常结束 / panic）都会执行。
	// cleanup 幂等（Stop 判空、RemoveAll 重复无害），注册越早覆盖越全。
	defer cleanup()

	dir := inst.Dir

	// /tmp 处理（tmpfs | host）仅校验参数合法性，非法值提前报错。
	if _, terr := perm.ParseTmp(spec.Tmp); terr != nil {
		return fail("%v", terr)
	}

	logw, err := os.OpenFile(filepath.Join(dir, "proxy.log"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fail("打开 proxy.log: %v", err)
	}
	defer logw.Close()

	// 程序级配置（~/.config/cwrap/config.toml）：可自定义 bwrap 与
	// xdg-dbus-proxy 的可执行路径；未配置时按 PATH 查找。
	prog, perr := config.LoadProgram()
	if perr != nil {
		return fail("%v", perr)
	}

	// --allow portal 的 D-Bus 规则注入必须发生在 NeedBuses 判断**之前**：
	// portal 预设包含对 org.freedesktop.portal.Desktop 的 talk/call 规则，
	// 没有它，沙箱内没有会话总线，GTK/GIO 会因伪造的 /.flatpak-info 把
	// DBUS_SESSION_BUS_ADDRESS 视作 "disabled:"（GLib ≥2.80 对 flatpak
	// 沙箱的约定），settings portal 与托盘全部失效。
	if perm.Has(spec.Allow, "portal") && !strings.Contains(strings.Join(spec.DBus, ","), "preset:portal") {
		spec.DBus = append(spec.DBus, "preset:portal")
	}

	// instanceID 每次运行唯一（inst.ID）：socket 目录名；portal 场景
	// 同时作为 .flatpak-info 的 instance-id 与 .flatpak/<id>/ 目录名。
	flatpakInfoContent := ""
	if perm.Has(spec.Allow, "portal") {
		flatpakInfoContent = generateFlatpakInfo(spec, inst.ID)
	}

	// D-Bus 代理（默认零规则，仅显式授权）。
	// portal 场景下代理由 bwrap 包装运行（对齐 flatpak add_bwrap_wrapper），
	// 使其命名空间根里可见 /.flatpak-info——portal 通过 /proc/<代理pid>/root
	// 读取它识别 caller 身份。包装 bwrap 同样接收 --sync-fd。
	session, system := dbusproxy.NeedBuses(spec)
	if session {
		addr, aerr := dbusproxy.SessionAddress()
		if aerr == nil {
			sessionProxy, aerr = dbusproxy.Start(prog.BwrapCmd(), prog.DBusProxyCmd(), addr,
				filepath.Join(dir, "session"), append(append([]string{}, spec.DBus...), spec.RawDBus...),
				[]byte(flatpakInfoContent), logw, syncR)
		}
		if aerr != nil {
			return fail("%v", aerr)
		}
	}
	if system {
		addr, ok := dbusproxy.SystemAddress()
		if !ok {
			return fail("宿主系统总线 socket 不存在（/run/dbus/system_bus_socket）")
		}
		sp, aerr := dbusproxy.Start(prog.BwrapCmd(), prog.DBusProxyCmd(), addr,
			filepath.Join(dir, "system"), append(append([]string{}, spec.DBus...), spec.RawDBus...),
			[]byte(flatpakInfoContent), logw, syncR)
		if aerr != nil {
			return fail("%v", aerr)
		}
		systemProxy = sp
	}

	// seccomp BPF（内存生成 -> memfd -> FD 传递）
	fdNo := func() int { return 3 + len(extraFiles) - 1 } // ExtraFiles 从 3 开始编号
	seccompFD := 0
	if spec.Seccomp != "" && spec.Seccomp != "off" {
		prog, gerr := seccomp.Generate(spec.Seccomp, spec.AllowSyscalls,
			perm.Has(spec.Allow, "devel"), perm.Has(spec.Harden, "sync"))
		if gerr != nil {
			return fail("%v", gerr)
		}
		seccompFile, err = seccomp.Memfd(prog)
		if err != nil {
			return fail("%v", err)
		}
		extraFiles = append(extraFiles, seccompFile)
		seccompFD = fdNo()
	}

	// --allow portal：规范 .flatpak-info 以 --ro-bind-data 挂到沙箱根。
	flatpakInfoFD := 0
	if perm.Has(spec.Allow, "portal") {
		f, ferr := memfdWrite("flatpak-info", flatpakInfoContent)
		if ferr != nil {
			return fail("%v", ferr)
		}
		extraFiles = append(extraFiles, f)
		flatpakInfoFD = fdNo()
	}

	// --allow portal：创建 $XDG_RUNTIME_DIR/.flatpak/<instance-id>/，
	// 打开 bwrapinfo.json 写端 fd，作为 --json-status-fd 交给 bwrap。
	// bwrap 在沙箱进程就绪后自行写入 { "child-pid": N }——这是
	// xdg-desktop-portal 反伪造验证的权威来源。切勿用手写 JSON 替代。
	statusFD := 0
	if perm.Has(spec.Allow, "portal") {
		portalDir = filepath.Join(xdgRuntimeDirForPortal(), ".flatpak", inst.ID)
		if merr := os.MkdirAll(portalDir, 0o700); merr != nil {
			return fail("创建 portal 实例目录 %s: %v", portalDir, merr)
		}
		bwrapInfoFile, err = os.OpenFile(filepath.Join(portalDir, "bwrapinfo.json"),
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return fail("打开 bwrapinfo.json: %v", err)
		}
		extraFiles = append(extraFiles, bwrapInfoFile)
		statusFD = fdNo()
	}

	// 网络后端（对齐 bubblejail slirp4netns / pasta_network 服务）：
	// 强制独立 netns，用 --info-fd 拿沙箱 PID 后在宿主侧挂接用户态网络栈。
	// portal 身份链的 child-pid 由 bwrap 通过 --json-status-fd 自行写入
	// bwrapinfo.json，info-fd 仅用于网络后端挂接；两者互不依赖。
	backend := spec.UserNetBackend()
	var netInfoR, netReadyR *os.File
	infoFD, netResolvFD := 0, 0
	if backend == "pasta" || backend == "slirp4netns" {
		r, w, perr := os.Pipe()
		if perr != nil {
			return fail("创建 info 管道: %v", perr)
		}
		extraFiles = append(extraFiles, w)
		infoFD = fdNo()
		netInfoR = r
	}
	if backend == "pasta" || backend == "slirp4netns" {
		f, rerr := memfdWrite("resolv.conf", "nameserver 10.0.2.3\n")
		if rerr != nil {
			return fail("%v", rerr)
		}
		extraFiles = append(extraFiles, f)
		netResolvFD = fdNo()
		if backend == "slirp4netns" {
			rr, rw, qerr := os.Pipe() // slirp4netns --ready-fd
			if qerr != nil {
				return fail("创建 ready 管道: %v", qerr)
			}
			extraFiles = append(extraFiles, rw)
			netReadyR = rr
		}
	}

	// 生命周期 sync-fd：读端交给主沙箱 bwrap（写端 syncW 由本进程持有）。
	extraFiles = append(extraFiles, syncR)
	syncFD := fdNo()

	uid := syscall.Getuid()
	// --allow portal：解析宿主 flatpak-xdg-utils 的 xdg-open 路径
	// （config.toml 的 xdg_open_path 优先，否则按发行版候选探测）。
	xdgOpenPath := ""
	if perm.Has(spec.Allow, "portal") {
		p2, w2 := bwrap.ResolveXDGOpen(prog.XDGOpenPath)
		if w2 != "" {
			fmt.Fprintln(os.Stderr, w2)
		}
		xdgOpenPath = p2
	}
	args, aerr := bwrap.Args(&bwrap.Options{
		Perm:            spec,
		UID:             uid,
		HomeDir:         spec.HomeDirHost(),
		SeccompFD:       seccompFD,
		DBusSessionPath: proxyPath(sessionProxy, filepath.Join(dir, "session")),
		DBusSystemPath:  proxyPath(systemProxy, filepath.Join(dir, "system")),
		XDGOpenPath:     xdgOpenPath,
		FlatpakInfoFD:   flatpakInfoFD,
		InfoFD:          infoFD,
		NetResolvFD:     netResolvFD,
		StatusFD:        statusFD,
		SyncFD:          syncFD,
		CmdPath:         argv[0],
		CmdArgs:         argv[1:],
	})
	if aerr != nil {
		return fail("%v", aerr)
	}

	// bwrap 参数经 --args FD 传递（bubblejail 同款方式），彻底规避 ARG_MAX，
	// 参数不再暴露在 /proc/<pid>/cmdline 中。
	//
	// bwrap --args 的语义（源码 bubblewrap.c，v0.11 确认）：
	//   1. fd 内容按 NUL 分割逐个作为参数；
	//   2. fd 内容被"递归解析"，遇到 "--" 即停止，其后内容被丢弃——
	//      因此 fd 只能放选项，"--" 与命令必须留在命令行；
	//   3. 命令行解析完若无剩余命令参数，bwrap 打印 usage 并以退出码 1 退出。
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	fdArgs, tailArgs := args, []string(nil)
	if sep >= 0 {
		fdArgs, tailArgs = args[:sep], args[sep:]
	}
	argsFile, werr := memfdWrite("cwrap-bwrap-args", strings.Join(fdArgs, "\x00")+"\x00")
	if werr != nil {
		return fail("%v", werr)
	}
	extraFiles = append(extraFiles, argsFile)
	argsFD := fdNo()

	// 命令行：--args <fd> + "--" 与命令（tailArgs 以 "--" 开头）
	cmd := exec.Command(prog.BwrapCmd(), append([]string{"--args", strconv.Itoa(argsFD)}, tailArgs...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = extraFiles
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return fail("启动 bwrap: %v（请确认已安装 bubblewrap）", err)
	}

	st, _ := procStartTicks(cmd.Process.Pid) // 失败为 0，killGroupSafe 会回退直发
	entry := &sandboxRef{pgid: cmd.Process.Pid, startTicks: st}

	// 读取沙箱 PID（--info-fd）：仅网络后端使用。
	sandboxPID := -1
	if infoFD > 0 {
		pid, rerr := readSandboxPID(netInfoR)
		netInfoR.Close() // 读端用后即关
		if rerr != nil {
			killGroupSafe(entry, syscall.SIGKILL)
			cmd.Wait()
			return fail("读取沙箱 PID 失败（网络后端需要）: %v", rerr)
		}
		sandboxPID = pid
	}

	// 网络后端挂接：拉起 pasta / slirp4netns
	var netBackendCmd *exec.Cmd
	if backend == "pasta" || backend == "slirp4netns" {
		nb, nerr := startNetBackend(backend, sandboxPID, spec.NetBackendArgs, netReadyR)
		if nerr != nil {
			killGroupSafe(entry, syscall.SIGKILL)
			cmd.Wait()
			return fail("启动网络后端 %s: %v", backend, nerr)
		}
		netBackendCmd = nb
	}

	// tty 前台进程组交接：沙箱是 cwrap 的直接子进程（同会话），
	// 交互程序才能正常读 tty。退出时恢复原前台组。
	tty := isTTY(os.Stdin)
	savedPgid := syscall.Getpgrp()
	if tty {
		signal.Ignore(syscall.SIGTTOU, syscall.SIGTTIN)
		setForegroundPGID(cmd.Process.Pid)
		defer restoreForeground(savedPgid)
	}

	// 信号转发：cwrap 收到的终止类信号转发给沙箱进程组；
	// SIGTERM/SIGHUP 宽限 3 秒后升级为 SIGKILL，避免卡死。
	// cwrap 自身被 SIGKILL 时无需转发——sync-fd 写端随进程关闭，
	// bwrap 立即回收沙箱。
	sigCh := make(chan os.Signal, 8)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	go func() {
		for s := range sigCh {
			sig := s.(syscall.Signal)
			killGroupSafe(entry, sig)
			if sig == syscall.SIGTERM || sig == syscall.SIGHUP {
				go func() {
					time.Sleep(3 * time.Second)
					killGroupSafe(entry, syscall.SIGKILL)
				}()
			}
		}
	}()

	waitErr := cmd.Wait()

	if netBackendCmd != nil && netBackendCmd.Process != nil {
		netBackendCmd.Process.Kill()
		netBackendCmd.Wait()
	}

	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			ws, _ := ee.Sys().(syscall.WaitStatus)
			switch {
			case ws.Signaled():
				fmt.Fprintf(os.Stderr, "cwrap: 进程被信号 %d 终止\n", int(ws.Signal()))
				return 128 + int(ws.Signal())
			case ws.Exited():
				return ws.ExitStatus()
			default:
				return ee.ExitCode()
			}
		}
		return fail("%v", waitErr)
	}
	return 0
}

func proxyPath(p *dbusproxy.Proxy, def string) string {
	if p == nil {
		return ""
	}
	return def
}

// xdgRuntimeDirForPortal 返回宿主侧运行时目录（bwrapinfo.json 的落盘位置）。
func xdgRuntimeDirForPortal() string {
	if v := os.Getenv("XDG_RUNTIME_DIR"); v != "" {
		return v
	}
	return fmt.Sprintf("/run/user/%d", syscall.Getuid())
}

// memfdWrite 把内容写入匿名 memfd 并回卷偏移（供 bwrap --ro-bind-data 读取）。
func memfdWrite(name, content string) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, 0)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	f := os.NewFile(uintptr(fd), name)
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// readSandboxPID 读取 bwrap --info-fd 写出的 {"pid":N}。
func readSandboxPID(r *os.File) (int, error) {
	r.SetReadDeadline(time.Now().Add(10 * time.Second))
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	var info struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(data), &info); err != nil {
		return 0, fmt.Errorf("解析 info JSON: %w", err)
	}
	if info.PID <= 0 {
		return 0, fmt.Errorf("info JSON 无有效 pid")
	}
	return info.PID, nil
}

// startNetBackend 在宿主侧拉起用户态网络栈，挂接沙箱 netns。
// pasta 直接附着到沙箱 PID；slirp4netns 通过 --ready-fd=3 等待就绪。
func startNetBackend(backend string, pid int, extraArgs []string, readyR *os.File) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	switch backend {
	case "pasta":
		args := append(append([]string{"--config-net"}, extraArgs...), strconv.Itoa(pid))
		cmd = exec.Command("pasta", args...)
	case "slirp4netns":
		args := append([]string{"--ready-fd=3"}, extraArgs...)
		args = append(args, strconv.Itoa(pid), "tap0")
		cmd = exec.Command("slirp4netns", args...)
		if readyR != nil {
			cmd.ExtraFiles = []*os.File{readyR}
		}
	default:
		return nil, fmt.Errorf("未知网络后端 %q", backend)
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if readyR != nil {
		defer readyR.Close() // 读端用后即关
		readyR.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1)
		if _, err := readyR.Read(buf); err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return nil, fmt.Errorf("slirp4netns 未在超时内就绪: %w", err)
		}
	}
	return cmd, nil
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
