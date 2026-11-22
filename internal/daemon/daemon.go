// Package daemon 实现 cwrapd：管理沙箱子进程生命周期与临时文件清理。
//
// 生命周期：首次 cwrap run 时自动拉起；空闲（无运行中子进程）超过
// IdleTimeout 后自动退出；启动时清扫上次异常退出留下的陈旧 socket 目录。
//
// 协议约定：所有客户端（含 ps/kill）连接后先通过 SCM_RIGHTS 发送
// 3 个 stdio FD，再发送一行 JSON Request（详见 internal/ipc）。
package daemon

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"cwrap/internal/bwrap"
	"cwrap/internal/config"
	"cwrap/internal/dbusproxy"
	"cwrap/internal/ipc"
	"cwrap/internal/perm"
	"cwrap/internal/seccomp"
)

// IdleTimeout 是 daemon 空闲自动退出的时限。
const IdleTimeout = 30 * time.Second

type runEntry struct {
	id         string
	app        string
	pgid       int
	cmd        *exec.Cmd
	dir        string
	startTicks uint64 // bwrap 的 /proc starttime，供 killGroupSafe 校验 pgid 归属
}

type Server struct {
	mu       sync.Mutex
	ln       net.Listener
	runs     map[string]*runEntry
	idleStop chan struct{}
	socket   string
}

// Run 启动 daemon（阻塞）。
func Run() error {
	if err := os.MkdirAll(filepath.Dir(ipcSocket()), 0o700); err != nil {
		return err
	}
	cleanStale()

	_ = os.Remove(ipcSocket()) // 无并发 daemon 时清掉残留 socket
	ln, err := net.Listen("unix", ipcSocket())
	if err != nil {
		return fmt.Errorf("监听 %s: %w", ipcSocket(), err)
	}
	if err := os.Chmod(ipcSocket(), 0o600); err != nil {
		return err
	}

	s := &Server{
		ln:       ln,
		runs:     map[string]*runEntry{},
		idleStop: make(chan struct{}, 16),
		socket:   ipcSocket(),
	}
	defer func() {
		ln.Close()
		os.Remove(s.socket)
	}()

	go s.idleLoop()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigc
		s.shutdown()
		os.Exit(0)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.idleStop:
				return nil
			default:
			}
			return err
		}
		s.resetIdle()
		go s.handle(conn)
	}
}

// procStartTicks 读取 /proc/<pid>/stat 的 starttime（第 22 字段，clock tick）。
// 进程存活期间该值不变，是区分"pgid 被内核回收复用"的唯一可靠依据。
func procStartTicks(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// comm 可含空格与括号，从最后一个 ')' 之后切分
	i := bytes.LastIndexByte(data, ')')
	if i < 0 || i+2 > len(data) {
		return 0, fmt.Errorf("stat 格式异常")
	}
	fields := strings.Fields(string(data[i+2:])) // fields[0] = state(第3字段)
	if len(fields) < 20 {
		return 0, fmt.Errorf("stat 字段不足")
	}
	return strconv.ParseUint(fields[19], 10, 64) // 第22字段 => fields[19]
}

// killGroupSafe 向沙箱进程组发信号。发送前用 starttime 校验 pgid 仍属于
// 当初启动的 bwrap，防止组退出后 pgid 被复用导致误杀。
func killGroupSafe(e *runEntry, sig syscall.Signal) {
	if e == nil || e.pgid <= 0 {
		return
	}
	if e.startTicks == 0 {
		syscall.Kill(-e.pgid, sig) // 启动瞬间没读到：回退直发，保可用性
		return
	}
	cur, err := procStartTicks(e.pgid)
	if err != nil || cur != e.startTicks {
		return // 组已退出或 pgid 已被复用：不补刀
	}
	syscall.Kill(-e.pgid, sig)
}

// devNullFD 供 ping 探活时填充协议要求的 3 个 stdio FD。
func devNullFD() int {
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return -1
	}
	return int(f.Fd())
}

func ipcSocket() string {
	p, _ := ipc.SocketPath()
	return p
}

func runtimeDir() string {
	return os.Getenv("XDG_RUNTIME_DIR")
}

func (s *Server) resetIdle() {
	select {
	case s.idleStop <- struct{}{}:
	default:
	}
}

func (s *Server) idleLoop() {
	t := time.NewTimer(IdleTimeout)
	for {
		select {
		case <-s.idleStop:
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
			t.Reset(IdleTimeout)
		case <-t.C:
			s.mu.Lock()
			for id, r := range s.runs {
				// 进程组已不存在：回收泄漏的 entry
				if syscall.Kill(r.pgid, 0) != nil {
					delete(s.runs, id)
				}
			}
			n := len(s.runs)
			s.mu.Unlock()
			if n == 0 {
				s.shutdown()
				os.Exit(0)
			}
			t.Reset(IdleTimeout)

		}
	}
}

func (s *Server) shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ln.Close()
	os.Remove(s.socket)
	for _, r := range s.runs {
		killGroupSafe(r, syscall.SIGTERM)
	}
	// 宽限后强制回收，避免异常沙箱在 daemon 退出后残留
	go func(entries []*runEntry) {
		time.Sleep(2 * time.Second)
		for _, r := range entries {
			killGroupSafe(r, syscall.SIGKILL)
		}
		os.Exit(0)
	}(func() []*runEntry {
		out := make([]*runEntry, 0, len(s.runs))
		for _, r := range s.runs {
			out = append(out, r)
		}
		return out
	}())
}

// cleanStale 清扫 pid 已死的陈旧运行目录。
func cleanStale() {
	base := filepath.Join(runtimeDir(), "cwrap")
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "cwrapd.sock" {
			continue
		}
		dir := filepath.Join(base, e.Name())
		pidFile := filepath.Join(dir, ".pid")
		data, err := os.ReadFile(pidFile)
		if err != nil {
			os.RemoveAll(dir)
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 0 {
			os.RemoveAll(dir)
			continue
		}
		if syscall.Kill(pid, 0) != nil {
			os.RemoveAll(dir)
		}
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}

	files, leftover, err := ipc.RecvFDs(uc, 3)
	if err != nil {
		ipc.WriteJSON(uc, ipc.Response{Ok: false, Error: "接收 stdio FD 失败: " + err.Error()})
		return
	}

	br := bufio.NewReader(io.MultiReader(bytes.NewReader(leftover), uc))
	var req ipc.Request
	if err := ipc.ReadJSON(br, &req); err != nil {
		ipc.WriteJSON(uc, ipc.Response{Ok: false, Error: "解析请求失败: " + err.Error()})
		return
	}

	switch req.Cmd {
	case "run":
		s.runSession(uc, br, &req, files)
	case "ps":
		s.handlePS(uc)
	case "kill":
		s.handleKill(uc, req.Target)
	case "ping":
		ipc.WriteJSON(uc, ipc.Response{Ok: true})
	default:
		ipc.WriteJSON(uc, ipc.Response{Ok: false, Error: "未知命令 " + req.Cmd})
	}

}

func (s *Server) handlePS(uc *net.UnixConn) {
	s.mu.Lock()
	runs := make([]ipc.RunInfo, 0, len(s.runs))
	for _, r := range s.runs {
		runs = append(runs, ipc.RunInfo{ID: r.id, App: r.app})
	}
	s.mu.Unlock()
	ipc.WriteJSON(uc, ipc.Response{Ok: true, Runs: runs})
}

func (s *Server) handleKill(uc *net.UnixConn, target string) {
	s.mu.Lock()
	var victim *runEntry
	for _, r := range s.runs {
		if r.id == target || r.app == target {
			victim = r
			break
		}
	}
	s.mu.Unlock()
	if victim == nil {
		ipc.WriteJSON(uc, ipc.Response{Ok: false, Error: "未找到运行中的沙箱: " + target})
		return
	}
	killGroupSafe(victim, syscall.SIGTERM)
	go func(e *runEntry) {
		time.Sleep(3 * time.Second)
		killGroupSafe(victim, syscall.SIGKILL)
	}(victim)
	ipc.WriteJSON(uc, ipc.Response{Ok: true})
}

// runSession 执行一次完整的沙箱运行。
func (s *Server) runSession(uc *net.UnixConn, br *bufio.Reader, req *ipc.Request, stdio []*os.File) {
	spec := req.Spec
	if spec == nil || len(req.Argv) == 0 {
		ipc.WriteJSON(uc, ipc.Response{Ok: false, Error: "run 请求缺少 spec 或 argv"})
		return
	}
	if len(stdio) < 3 {
		ipc.WriteJSON(uc, ipc.Response{Ok: false, Error: "stdio FD 数量不足"})
		return
	}

	dir, id, err := dbusproxy.SocketDir(runtimeDir())
	if err != nil {
		ipc.WriteJSON(uc, ipc.Response{Ok: false, Error: "创建运行目录: " + err.Error()})
		return
	}

	// 这四个变量必须在 cleanup 闭包定义之前用 var 声明——闭包通过引用
	// 捕获它们，赋值可以晚于闭包定义，但声明不能晚于闭包定义（Go 词法
	// 作用域规则）。bwrapInfoFile / instanceDir 仅在 --allow portal 时赋值，
	// 由 cleanup 在退出/失败路径统一关闭与清理。
	var sessionProxy, systemProxy *dbusproxy.Proxy
	var seccompFile *os.File
	var bwrapInfoFile *os.File
	var instanceDir string

	cleanup := func() {
		stopBoth(sessionProxy, systemProxy)
		if seccompFile != nil {
			seccompFile.Close()
			seccompFile = nil
		}
		if bwrapInfoFile != nil {
			bwrapInfoFile.Close()
			bwrapInfoFile = nil
		}
		if instanceDir != "" {
			os.RemoveAll(instanceDir)
			instanceDir = ""
		}
		os.RemoveAll(dir)
	}
	// 唯一清理出口：无论哪条路径返回（fail / 正常结束 / panic）都会执行。
	// cleanup 幂等（Stop 判空、RemoveAll 重复无害），注册越早覆盖越全。
	defer cleanup()

	fail := func(format string, a ...any) {
		ipc.WriteJSON(uc, ipc.Response{Ok: false, Error: fmt.Sprintf(format, a...)})
	}

	// /tmp 处理（tmpfs | host）不涉及宿主侧目录准备，
	// 仅校验参数合法性，非法值提前报错。
	if _, terr := perm.ParseTmp(spec.Tmp); terr != nil {
		fail("%v", terr)
		return
	}

	logw, err := os.OpenFile(filepath.Join(dir, "proxy.log"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fail("打开 proxy.log: %v", err)
		return
	}
	defer logw.Close()

	// 程序级配置（~/.config/cwrap/config.toml）：可自定义 bwrap 与
	// xdg-dbus-proxy 的可执行路径；未配置时按 PATH 查找。
	prog, perr := config.LoadProgram()
	if perr != nil {
		fail("%v", perr)
		return
	}

	// --allow portal 的 D-Bus 规则注入必须发生在 NeedBuses 判断**之前**：
	// portal 预设包含对 org.freedesktop.portal.Desktop 的 talk/call 规则，
	// 没有它，沙箱内没有会话总线，GTK/GIO 会因伪造的 /.flatpak-info 把
	// DBUS_SESSION_BUS_ADDRESS 视作 "disabled:"（GLib ≥2.80 对 flatpak
	// 沙箱的约定），settings portal 与托盘全部失效。
	if perm.Has(spec.Allow, "portal") && !strings.Contains(strings.Join(spec.DBus, ","), "preset:portal") {
		spec.DBus = append(spec.DBus, "preset:portal")
	}

	// --allow portal：按应用独立生成 instance-id 与规范 .flatpak-info。
	// instance-id 同时作为 $XDG_RUNTIME_DIR/.flatpak/<id>/ 目录名——
	// portal 先读代理命名空间里的 /.flatpak-info 拿到 instance-id，
	// 再去该目录读 bwrapinfo.json 验证 child-pid。
	var instanceID, flatpakInfoContent string
	if perm.Has(spec.Allow, "portal") {
		instanceID = newInstanceID()
		flatpakInfoContent = generateFlatpakInfo(spec, instanceID)
	}

	// D-Bus 代理（默认零规则，仅显式授权）。
	// portal 场景下代理由 bwrap 包装运行（对齐 flatpak add_bwrap_wrapper），
	// 使其命名空间根里可见 /.flatpak-info——portal 通过 /proc/<代理pid>/root
	// 读取它识别 caller 身份。
	session, system := dbusproxy.NeedBuses(spec)
	if session {
		addr, aerr := dbusproxy.SessionAddress()
		if aerr == nil {
			sessionProxy, aerr = dbusproxy.Start(prog.BwrapCmd(), prog.DBusProxyCmd(), addr,
				filepath.Join(dir, "session"), spec.DBus, []byte(flatpakInfoContent), logw)
		}
		if aerr != nil {
			fail("%v", aerr)
			return
		}
	}
	if system {
		addr, ok := dbusproxy.SystemAddress()
		if !ok {
			fail("宿主系统总线 socket 不存在（/run/dbus/system_bus_socket）")
			return
		}
		sp, aerr := dbusproxy.Start(prog.BwrapCmd(), prog.DBusProxyCmd(), addr,
			filepath.Join(dir, "system"), spec.DBus, []byte(flatpakInfoContent), logw)
		if aerr != nil {
			fail("%v", aerr)
			return
		}
		systemProxy = sp
	}

	// seccomp BPF（内存生成 -> memfd -> FD 传递）
	extraFiles := []*os.File{}
	fdNo := func() int { return 3 + len(extraFiles) - 1 } // ExtraFiles 从 3 开始编号
	seccompFD := 0
	if spec.Seccomp != "" && spec.Seccomp != "off" {
		prog, gerr := seccomp.Generate(spec.Seccomp, spec.AllowSyscalls,
			perm.Has(spec.Allow, "devel"), perm.Has(spec.Harden, "sync"))
		if gerr != nil {
			fail("%v", gerr)
			return
		}
		seccompFile, err = seccomp.Memfd(prog)
		if err != nil {
			fail("%v", err)
			return
		}
		extraFiles = append(extraFiles, seccompFile)
		seccompFD = fdNo()
	}

	// --allow portal：规范 .flatpak-info 以 --ro-bind-data 挂到沙箱根。
	flatpakInfoFD := 0
	if perm.Has(spec.Allow, "portal") {
		f, ferr := memfdWrite("flatpak-info", flatpakInfoContent)
		if ferr != nil {
			fail("%v", ferr)
			return
		}
		extraFiles = append(extraFiles, f)
		flatpakInfoFD = fdNo()
	}

	// --allow portal：创建 $XDG_RUNTIME_DIR/.flatpak/<instance-id>/，
	// 打开 bwrapinfo.json 写端 fd，作为 --json-status-fd 交给 bwrap。
	// bwrap 在沙箱进程就绪后自行写入 { "child-pid": N }——这是
	// xdg-desktop-portal 反伪造验证的权威来源。切勿用手写 JSON 替代
	// （原 writeInstanceMeta 的做法既无法保证 child-pid 是 bwrap 视图
	// 内的真实值，也与 bwrap 写出的格式存在字段/时序偏差）。
	statusFD := 0
	if perm.Has(spec.Allow, "portal") && instanceID != "" {
		instanceDir = filepath.Join(xdgRuntimeDirForPortal(), ".flatpak", instanceID)
		if merr := os.MkdirAll(instanceDir, 0o700); merr != nil {
			fail("创建 portal 实例目录 %s: %v", instanceDir, merr)
			return
		}
		bwrapInfoFile, err = os.OpenFile(filepath.Join(instanceDir, "bwrapinfo.json"),
			os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			fail("打开 bwrapinfo.json: %v", err)
			return
		}
		extraFiles = append(extraFiles, bwrapInfoFile)
		statusFD = fdNo()
	}

	// 网络后端（对齐 bubblejail slirp4netns / pasta_network 服务）：
	// 强制独立 netns，用 --info-fd 拿沙箱 PID 后在宿主侧挂接用户态网络栈。
	//
	// 注意：--info-fd 的启用条件已不再包含 --allow portal。
	// portal 身份链的 child-pid 由 bwrap 通过 --json-status-fd 自行
	// 写入 bwrapinfo.json，info-fd 仅用于网络后端挂接；两者互不依赖，
	// portal 场景不再因为 info-fd 读取超时而整体失败。
	backend := spec.UserNetBackend()
	var netInfoR, netReadyR *os.File
	infoFD, netResolvFD := 0, 0
	if backend == "pasta" || backend == "slirp4netns" {
		r, w, perr := os.Pipe()
		if perr != nil {
			fail("创建 info 管道: %v", perr)
			return
		}
		extraFiles = append(extraFiles, w)
		infoFD = fdNo()
		netInfoR = r
	}
	if backend == "pasta" || backend == "slirp4netns" {
		f, rerr := memfdWrite("resolv.conf", "nameserver 10.0.2.3\n")
		if rerr != nil {
			fail("%v", rerr)
			return
		}
		extraFiles = append(extraFiles, f)
		netResolvFD = fdNo()
		if backend == "slirp4netns" {
			rr, rw, qerr := os.Pipe() // slirp4netns --ready-fd
			if qerr != nil {
				fail("创建 ready 管道: %v", qerr)
				return
			}
			extraFiles = append(extraFiles, rw)
			netReadyR = rr
		}
	}

	uid := syscall.Getuid()
	args, aerr := bwrap.Args(&bwrap.Options{
		Perm:            spec,
		UID:             uid,
		HomeDir:         spec.HomeDirHost(),
		SeccompFD:       seccompFD,
		DBusSessionPath: proxyPath(sessionProxy, filepath.Join(dir, "session")),
		DBusSystemPath:  proxyPath(systemProxy, filepath.Join(dir, "system")),
		FlatpakInfoFD:   flatpakInfoFD,
		InfoFD:          infoFD,
		NetResolvFD:     netResolvFD,
		StatusFD:        statusFD,
		CmdPath:         req.Argv[0],
		CmdArgs:         req.Argv[1:],
	})
	if aerr != nil {
		fail("%v", aerr)
		return
	}

	// bwrap 参数经 --args FD 传递（bubblejail 同款方式），彻底规避 ARG_MAX，
	// 参数不再暴露在 /proc/<pid>/cmdline 中。
	//
	// bwrap --args 的语义（源码 bubblewrap.c，v0.11 确认）：
	//   1. fd 内容按 NUL 分割逐个作为参数；
	//   2. fd 内容被"递归解析"，遇到 "--" 即停止，其后内容被丢弃且
	//      不会回传外层——因此 fd 只能放选项，"--" 与命令必须留在命令行；
	//   3. 解析完 fd 后，bwrap 继续解析命令行剩余参数；命令行解析完
	//      若无剩余命令参数，bwrap 会打印 usage 并以退出码 1 退出
	//      （无错误信息，argc <= 0 → usage(EXIT_FAILURE, stderr)）。
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
		fail("%v", werr)
		return
	}
	extraFiles = append(extraFiles, argsFile)
	argsFD := fdNo()

	// 命令行：--args <fd> + "--" 与命令（tailArgs 以 "--" 开头）
	cmd := exec.Command(prog.BwrapCmd(), append([]string{"--args", strconv.Itoa(argsFD)}, tailArgs...)...)
	cmd.Stdin = stdio[0]
	cmd.Stdout = stdio[1]
	cmd.Stderr = stdio[2]
	cmd.ExtraFiles = extraFiles
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		cleanup()
		ipc.WriteJSON(uc, ipc.Response{Ok: false, Error: "启动 bwrap: " + err.Error() + "（请确认已安装 bubblewrap）"})
		return
	}

	st, _ := procStartTicks(cmd.Process.Pid) // 失败为 0，killGroupSafe 会回退直发
	entry := &runEntry{id: id, app: spec.App, cmd: cmd, dir: dir,
		pgid: cmd.Process.Pid, startTicks: st}

	// 读取沙箱 PID（--info-fd）：仅网络后端使用。
	// portal 身份链不依赖此值——bwrap 已通过 --json-status-fd 把
	// child-pid 写入 bwrapinfo.json。此处超时仅影响网络后端。
	sandboxPID := -1
	if infoFD > 0 {
		pid, rerr := readSandboxPID(netInfoR)
		if rerr != nil {
			killGroupSafe(entry, syscall.SIGKILL)
			cmd.Wait()
			cleanup()
			ipc.WriteJSON(uc, ipc.Response{Ok: false, Error: "读取沙箱 PID 失败（网络后端需要）: " + rerr.Error()})
			return
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
			cleanup()
			ipc.WriteJSON(uc, ipc.Response{Ok: false, Error: "启动网络后端 " + backend + ": " + nerr.Error()})
			return
		}
		netBackendCmd = nb
	}

	s.mu.Lock()
	s.runs[id] = entry
	s.mu.Unlock()
	s.resetIdle()
	// entry 一定被移除：无论正常结束、卡死后被 KILL、还是异常路径
	defer func() {
		s.mu.Lock()
		delete(s.runs, id)
		s.mu.Unlock()
		s.resetIdle()
	}()

	// 通知客户端子进程组（交互程序 tcsetpgrp 需要）
	ipc.WriteJSON(uc, ipc.Event{Event: "started", ID: id, App: spec.App, PGID: entry.pgid})

	// 信号转发 + 客户端断开检测
	sigCh := make(chan int, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			var m ipc.SignalMsg
			if err := ipc.ReadJSON(br, &m); err != nil {
				killGroupSafe(entry, syscall.SIGTERM)
				go func(e *runEntry) {
					time.Sleep(2 * time.Second)
					killGroupSafe(e, syscall.SIGKILL)
				}(entry)
				return
			}
			if m.Cmd == "signal" {
				select {
				case sigCh <- m.Sig:
				default:
				}
			}
		}
	}()

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	var waitErr error
loop:
	for {
		select {
		case sig := <-sigCh:
			killGroupSafe(entry, syscall.Signal(sig))
		case <-done:
			select {
			case waitErr = <-waitCh:
			case <-time.After(3 * time.Second):
				killGroupSafe(entry, syscall.SIGKILL)
				waitErr = <-waitCh
			}
			break loop
		case waitErr = <-waitCh:
			break loop
		}
	}

	// 清理并应答
	s.resetIdle()
	if netBackendCmd != nil && netBackendCmd.Process != nil {
		netBackendCmd.Process.Kill()
		netBackendCmd.Wait()
	}

	resp := ipc.Response{Ok: true}
	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			ws, _ := ee.Sys().(syscall.WaitStatus)
			switch {
			case ws.Signaled():
				resp.ExitCode = -1
				resp.Signal = int(ws.Signal())
			case ws.Exited():
				resp.ExitCode = ws.ExitStatus()
			default:
				resp.ExitCode = ee.ExitCode()
			}
		} else {
			resp.Ok = false
			resp.Error = waitErr.Error()
		}
	}
	ipc.WriteJSON(uc, resp)
}

func proxyPath(p *dbusproxy.Proxy, def string) string {
	if p == nil {
		return ""
	}
	return def
}

func stopBoth(a, b *dbusproxy.Proxy) {
	a.Stop()
	b.Stop()
}

// newInstanceID 生成 32 位 hex 随机实例 ID（对齐 flatpak Instance.instance-id）。
func newInstanceID() string {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return fmt.Sprintf("%032x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// dbusNameSegment 把应用名清洗为合法的 D-Bus app-id 段：
// 仅保留 [a-z0-9_-]（小写），段首必须是字母（xdp_is_valid_app_id 的
// flatpak 规则），不满足时补 "app-" 前缀。
func dbusNameSegment(app string) string {
	s := strings.ToLower(app)
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			b.WriteRune(c)
		default:
			b.WriteByte('-') // 非法字符（空格、点、符号等）折叠为连字符
		}
	}
	seg := strings.Trim(b.String(), "-")
	if seg == "" || !(seg[0] >= 'a' && seg[0] <= 'z') {
		seg = "app-" + seg
	}
	return seg
}

// flatpakAppName 返回伪造 .flatpak-info 的 [Application] name：
// 按应用独立（xdg-desktop-portal 与 GIO document portal 客户端都以它
// 构造 by-app 授权身份），无应用名时回退 org.cwrap.Sandbox。
func flatpakAppName(spec *perm.Permissions) string {
	if spec.App == "" {
		return "org.cwrap.Sandbox"
	}
	return "org.cwrap.App." + dbusNameSegment(spec.App)
}

// generateFlatpakInfo 生成规范形态的 /.flatpak-info（对齐 flatpak 元数据）：
// xdg-desktop-portal 读取 [Application] name 与 [Instance] instance-id
// 识别 caller；GIO document portal 客户端读 name 构造 by-app URI；
// [Context]/[Session Bus Policy]/[System Bus Policy] 为规范字段。
func generateFlatpakInfo(spec *perm.Permissions, instanceID string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Application]\n")
	fmt.Fprintf(&b, "name=%s\n", flatpakAppName(spec))
	fmt.Fprintf(&b, "runtime=org.cwrap.Platform/x86_64/stable\n")
	fmt.Fprintf(&b, "\n[Instance]\n")
	fmt.Fprintf(&b, "instance-id=%s\n", instanceID)
	fmt.Fprintf(&b, "\n[Context]\n")
	fmt.Fprintf(&b, "shared=%s;\n", strings.Join(spec.Share, ";"))
	fmt.Fprintf(&b, "sockets=%s;\n", strings.Join(spec.Socket, ";"))
	fmt.Fprintf(&b, "devices=%s;\n", strings.Join(spec.Device, ";"))
	fmt.Fprintf(&b, "filesystems=%s;\n", strings.Join(spec.FS, ";"))

	// [Session Bus Policy] / [System Bus Policy]：talk/own/see 规则
	// （call/broadcast 不属于该节）。预设先展开，保证与代理规则一致。
	tokens, err := perm.ExpandDbusPresets(spec.DBus)
	if err != nil {
		tokens = spec.DBus
	}
	sessionPolicy, systemPolicy := []string{}, []string{}
	for _, tok := range tokens {
		tgt, name, ok := strings.Cut(tok, "=")
		if !ok || name == "" {
			continue
		}
		bus, pol, ok := strings.Cut(tgt, ".")
		if !ok {
			continue
		}
		switch pol {
		case "talk", "own", "see":
			switch bus {
			case "session":
				sessionPolicy = append(sessionPolicy, fmt.Sprintf("%s=%s", name, pol))
			case "system":
				systemPolicy = append(systemPolicy, fmt.Sprintf("%s=%s", name, pol))
			}
		}
	}
	if len(sessionPolicy) > 0 {
		fmt.Fprintf(&b, "\n[Session Bus Policy]\n")
		for _, l := range sessionPolicy {
			fmt.Fprintf(&b, "%s\n", l)
		}
	}
	if len(systemPolicy) > 0 {
		fmt.Fprintf(&b, "\n[System Bus Policy]\n")
		for _, l := range systemPolicy {
			fmt.Fprintf(&b, "%s\n", l)
		}
	}
	return b.String()
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
		// 等待 slirp4netns 就绪信号（超时 5s）
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

// EnsureRunning 若 daemon 未运行则拉起（fork 自身执行 `daemon` 子命令）。
func EnsureRunning() error {
	sock := ipcSocket()
	if sock == "" {
		return fmt.Errorf("XDG_RUNTIME_DIR 未设置，无法定位 cwrapd socket")
	}
	if daemonAlive(sock) {
		return nil
	}
	// socket 文件残留但对 ping 无应答（wedged/stopped 的旧 daemon）：清掉重绑
	_ = os.Remove(sock)

	base := filepath.Join(runtimeDir(), "cwrap")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return err
	}
	logf, err := os.OpenFile(filepath.Join(base, "cwrapd.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "daemon")
	cmd.Stdout = logf
	cmd.Stderr = logf
	// 关键：新会话 + 脱离控制终端 + 自成进程组。
	// 不做这一步，daemon 会继承客户端的 pgid/会话/tty，
	// 落入终端 job control 的 T（stopped）状态：SIGTERM 挂起、
	// 定时器冻结（闲时退出失效），只能 SIGKILL。
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("拉起 cwrapd: %w", err)
	}
	cmd.Process.Release() // 客户端不等待 daemon，避免僵尸

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if daemonAlive(sock) {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("cwrapd 未能在 3 秒内就绪（日志: %s）", filepath.Join(base, "cwrapd.log"))
}

// daemonAlive 真探活：拨通 socket 还不够——内核会代答 connect，
// 即使监听进程处于 stopped 状态也能拨通。必须走一轮完整 ping 应答。
func daemonAlive(sock string) bool {
	conn, err := net.DialTimeout("unix", sock, 300*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	uc := conn.(*net.UnixConn)
	nulls := []int{devNullFD(), devNullFD(), devNullFD()}
	if err := ipc.SendFDs(uc, nulls); err != nil {
		return false
	}
	if err := ipc.WriteJSON(uc, ipc.Request{Cmd: "ping"}); err != nil {
		return false
	}
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	var resp ipc.Response
	return ipc.ReadJSON(bufio.NewReader(uc), &resp) == nil && resp.Ok
}
