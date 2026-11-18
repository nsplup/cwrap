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

	"cwrap/internal/bwrap"
	"cwrap/internal/dbusproxy"
	"cwrap/internal/ipc"
	"cwrap/internal/perm"
	"cwrap/internal/seccomp"
)

// IdleTimeout 是 daemon 空闲自动退出的时限。
const IdleTimeout = 30 * time.Second

type runEntry struct {
	id   string
	app  string
	pgid int
	cmd  *exec.Cmd
	dir  string
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
		if r.pgid > 0 {
			syscall.Kill(-r.pgid, syscall.SIGTERM)
		}
	}
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
	syscall.Kill(-victim.pgid, syscall.SIGTERM)
	go func(e *runEntry) {
		time.Sleep(3 * time.Second)
		syscall.Kill(-e.pgid, syscall.SIGKILL)
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

	var sessionProxy, systemProxy *dbusproxy.Proxy
	var seccompFile *os.File
	cleanup := func() {
		stopBoth(sessionProxy, systemProxy)
		if seccompFile != nil {
			seccompFile.Close()
			seccompFile = nil
		}
		os.RemoveAll(dir)
	}
	// 唯一清理出口：无论哪条路径返回（fail / 正常结束 / panic）都会执行。
	// cleanup 幂等（Stop 判空、RemoveAll 重复无害），注册越早覆盖越全。
	defer cleanup()

	fail := func(format string, a ...any) {
		ipc.WriteJSON(uc, ipc.Response{Ok: false, Error: fmt.Sprintf(format, a...)})
	}

	logw, err := os.OpenFile(filepath.Join(dir, "proxy.log"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fail("打开 proxy.log: %v", err)
		return
	}
	defer logw.Close()

	// D-Bus 代理（默认零规则，仅显式授权）
	session, system := dbusproxy.NeedBuses(spec)
	if session {
		addr, aerr := dbusproxy.SessionAddress()
		if aerr == nil {
			sessionProxy, aerr = dbusproxy.Start(addr, filepath.Join(dir, "session"), spec.DBus, logw)
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
		sp, aerr := dbusproxy.Start(addr, filepath.Join(dir, "system"), spec.DBus, logw)
		if aerr != nil {
			fail("%v", aerr)
			return
		}
		systemProxy = sp
	}

	// seccomp BPF（内存生成 -> memfd -> FD 传递）
	extraFiles := []*os.File{}
	seccompFD := 0
	if spec.Seccomp != "" && spec.Seccomp != "off" {
		prog, gerr := seccomp.Generate(spec.Seccomp, spec.AllowSyscalls, perm.Has(spec.Allow, "devel"))
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
		seccompFD = 3 // ExtraFiles 从 3 开始编号
	}

	uid := syscall.Getuid()
	args, aerr := bwrap.Args(&bwrap.Options{
		Perm:            spec,
		UID:             uid,
		HomeDir:         spec.HomeDirHost(),
		SeccompFD:       seccompFD,
		DBusSessionPath: proxyPath(sessionProxy, filepath.Join(dir, "session")),
		DBusSystemPath:  proxyPath(systemProxy, filepath.Join(dir, "system")),
		CmdPath:         req.Argv[0],
		CmdArgs:         req.Argv[1:],
	})
	if aerr != nil {
		fail("%v", aerr)
		return
	}

	cmd := exec.Command("bwrap", args...)
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

	entry := &runEntry{id: id, app: spec.App, cmd: cmd, dir: dir, pgid: cmd.Process.Pid}
	s.mu.Lock()
	s.runs[id] = entry
	s.mu.Unlock()
	s.resetIdle()

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
				// 客户端断开或出错：终止沙箱进程组
				syscall.Kill(-entry.pgid, syscall.SIGTERM)
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
			syscall.Kill(-entry.pgid, syscall.Signal(sig))
		case <-done:
			waitErr = <-waitCh
			break loop
		case waitErr = <-waitCh:
			break loop
		}
	}

	// 清理并应答
	s.mu.Lock()
	delete(s.runs, id)
	s.mu.Unlock()
	s.resetIdle()

	resp := ipc.Response{Ok: true}
	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			resp.ExitCode = ee.ExitCode()
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

// EnsureRunning 若 daemon 未运行则拉起（fork 自身执行 `daemon` 子命令）。
func EnsureRunning() error {
	sock := ipcSocket()
	if sock == "" {
		return fmt.Errorf("XDG_RUNTIME_DIR 未设置，无法定位 cwrapd socket")
	}
	if daemonAlive(sock) {
		return nil
	}
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
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("拉起 cwrapd: %w", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if daemonAlive(sock) {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("cwrapd 未能在 3 秒内就绪（日志: %s）", filepath.Join(base, "cwrapd.log"))
}

func daemonAlive(sock string) bool {
	conn, err := net.DialTimeout("unix", sock, 300*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
