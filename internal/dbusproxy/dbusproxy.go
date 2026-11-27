// Package dbusproxy 封装 xdg-dbus-proxy。
//
// 默认零放行：只有提供了显式的 talk/own/see/call/broadcast 规则才会被
// 加入白名单；未请求任何 D-Bus 权限时不启动代理。
// socket 文件统一写入 $XDG_RUNTIME_DIR/cwrap/<时间戳>/ 下。
package dbusproxy

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"cwrap/internal/config"
	"cwrap/internal/perm"
)

// SessionAddress 返回宿主会话总线地址。
func SessionAddress() (string, error) {
	if a := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); a != "" {
		return a, nil
	}
	return "", fmt.Errorf("宿主未设置 DBUS_SESSION_BUS_ADDRESS，无法代理会话总线")
}

// SystemAddress 返回系统总线地址（socket 存在才可用）。
func SystemAddress() (string, bool) {
	const p = "/run/dbus/system_bus_socket"
	if _, err := os.Stat(p); err != nil {
		return "", false
	}
	return "unix:path=" + p, true
}

// Proxy 是一个已就绪的 xdg-dbus-proxy 进程。
type Proxy struct {
	cmd   *exec.Cmd
	ready *os.File // sync 管道读端：由 cwrap 主进程持有到代理退出，绝不提前关闭
}

// NeedBuses 根据权限判断需要代理哪些总线。
// 直通逃生门（--socket session-bus/system-bus）不走代理，由 bwrap 直接挂载。
func NeedBuses(p *perm.Permissions) (session, system bool) {
	tokens, _ := perm.ExpandDbusPresets(p.DBus) // 语法错误由 Validate 负责
	if perm.Has(p.Socket, "session-bus") {
		session = false // 直通：不启动代理
	} else {
		for _, d := range tokens {
			if strings.HasPrefix(d, "session.") {
				session = true
			}
		}
	}
	if perm.Has(p.Socket, "system-bus") {
		system = false // 直通：不启动代理
	} else {
		for _, d := range tokens {
			if strings.HasPrefix(d, "system.") {
				system = true
			}
		}
	}
	return
}

// filterRules 按总线前缀过滤规则；"-" 开头的 token 为原样透传的
// xdg-dbus-proxy 参数（--dbus-arg），始终保留。
func filterRules(rules []string, bus string) []string {
	var out []string
	for _, r := range rules {
		if strings.HasPrefix(r, "-") {
			out = append(out, r)
			continue
		}
		if strings.HasPrefix(r, bus+".") {
			out = append(out, r)
		}
	}
	return out
}

// dbusProxyArgs 把 perm 层规则 token 翻译成 xdg-dbus-proxy 参数。
// 支持目标：talk / own / see / call / broadcast（对齐 bubblejail 的
// DbusSessionCall 等；call/broadcast 支持 NAME=iface.glob@path 语法）。
// "-" 开头的 token 原样透传。
func dbusProxyArgs(rules []string) ([]string, error) {
	var args []string
	for _, r := range rules {
		if strings.HasPrefix(r, "-") {
			args = append(args, r)
			continue
		}
		tgt, name, ok := strings.Cut(r, "=")
		if !ok || name == "" {
			return nil, fmt.Errorf("非法 --dbus 规则 %q（应为 session.talk=NAME 等）", r)
		}
		verb := strings.TrimPrefix(tgt, "session.")
		verb = strings.TrimPrefix(verb, "system.")
		switch verb {
		case "talk":
			args = append(args, "--talk="+name)
		case "own":
			args = append(args, "--own="+name)
		case "see":
			args = append(args, "--see="+name)
		case "call":
			args = append(args, "--call="+name)
		case "broadcast":
			args = append(args, "--broadcast="+name)
		default:
			return nil, fmt.Errorf("无效的 --dbus 规则类型 %q", tgt)
		}
	}
	return args, nil
}

// Start 启动代理并等待就绪。
//
// proxyPath 为 xdg-dbus-proxy 可执行路径（空串 = 按 PATH 查找）；
// addr/socketPath 为总线地址与 socket 输出路径；rules 为 perm 层 token
// （自动按总线前缀过滤）。readyFD 通过 ExtraFiles 传入（固定为子进程
// fd 3），代理就绪后向其写一个字节。
//
// 全部位置参数与规则经 --args=4（fd 4）传递，命令行只保留 --fd=3 与
// --args=4：彻底规避 ARG_MAX，参数也不再暴露在 /proc/<pid>/cmdline。
//
// flatpakInfo 非 nil 时，代理由 bwrap 包装运行（对齐 flatpak
// add_bwrap_wrapper）：宿主根目录逐项挂入代理命名空间，并把规范形态的
// /.flatpak-info 以 --ro-bind-data 挂到代理的根。这是 xdg-desktop-portal
// 识别 caller 身份的前提——portal 经 /proc/<代理pid>/root/.flatpak-info
// 读取 name 与 instance-id（instance-id 的运行时验证由 bwrap 经
// --json-status-fd 写入 $XDG_RUNTIME_DIR/.flatpak/<id>/bwrapinfo.json 完成）。
func Start(bwrapPath, proxyPath, addr, socketPath string, rules []string, flatpakInfo []byte, logw io.Writer) (*Proxy, error) {
	bus := "session"
	if strings.HasPrefix(filepath.Base(socketPath), "system") {
		bus = "system"
	}
	expanded, perr := perm.ExpandDbusPresets(rules)
	if perr != nil {
		return nil, perr
	}
	mapped, err := dbusProxyArgs(filterRules(expanded, bus))
	if err != nil {
		return nil, err
	}
	readyR, readyW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	// 代理的位置参数与规则经 --args=FD 传入（NUL 分隔）
	proxyArgsContent := append([]string{addr, socketPath, "--filter"}, mapped...)
	proxyArgsFile, err := memfdArgs("cwrap-dbus-proxy-args", proxyArgsContent)
	if err != nil {
		readyR.Close()
		readyW.Close()
		return nil, err
	}
	if proxyPath == "" {
		proxyPath = config.DefaultDBusProxyCmd
	}
	// bwrap 在沙箱命名空间内按给定路径 exec 代理，绝对化以稳定解析
	if !strings.ContainsRune(proxyPath, '/') {
		if abs, lerr := exec.LookPath(proxyPath); lerr == nil {
			proxyPath = abs
		}
	}

	var cmd *exec.Cmd
	if len(flatpakInfo) == 0 {
		// 未启用 portal 包：无需求身份，直接运行代理。
		// fd 3 = ready 同步管道；fd 4 = 代理参数文件
		cmd = exec.Command(proxyPath, "--fd=3", "--args=4")
		cmd.ExtraFiles = []*os.File{readyW, proxyArgsFile}
	} else {
		// fd 3 = ready 同步管道；fd 4 = 包装 bwrap 参数；fd 5 = 代理参数；
		// fd 6 = .flatpak-info（--ro-bind-data）
		infoFile, ierr := memfdBytes("cwrap-flatpak-info", flatpakInfo)
		if ierr != nil {
			readyR.Close()
			readyW.Close()
			proxyArgsFile.Close()
			return nil, ierr
		}
		wArgs := dbusProxyWrapperArgs(filepath.Dir(socketPath), 6)
		wArgsFile, werr := memfdArgs("cwrap-bwrap-proxy-args", wArgs)
		if werr != nil {
			readyR.Close()
			readyW.Close()
			proxyArgsFile.Close()
			infoFile.Close()
			return nil, werr
		}
		if bwrapPath == "" {
			bwrapPath = config.DefaultBwrapCmd
		}
		// 命令行：bwrap --args 4 -- xdg-dbus-proxy --fd=3 --args=5
		//（--args fd 内容遇 "--" 停止，命令必须留在命令行，见 run 包同款注释）
		cmd = exec.Command(bwrapPath, "--args", "4", "--", proxyPath, "--fd=3", "--args=5")
		cmd.ExtraFiles = []*os.File{readyW, wArgsFile, proxyArgsFile, infoFile}
	}
	cmd.Stdout = logw
	cmd.Stderr = logw
	// 包装 bwrap（或未包装时的代理自身）独占一个进程组：Stop 超时以
	// kill(-pgid, SIGKILL) 整组回收，避免"只杀包装 bwrap → 代理（其子
	// 进程）变孤儿继续运行"。无 portal 分支下代理自己就是组首，行为等价。
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		readyR.Close()
		readyW.Close()
		return nil, fmt.Errorf("启动 xdg-dbus-proxy（%s）: %w", proxyPath, err)
	}
	readyW.Close() // 父进程侧立刻关闭写端
	proxyArgsFile.Close()

	pr := &Proxy{cmd: cmd, ready: readyR}
	// 等待就绪信号（带超时）
	readyR.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 1)
	if _, err := readyR.Read(buf); err != nil {
		pr.Stop()
		return nil, fmt.Errorf("xdg-dbus-proxy 未在超时内就绪: %w", err)
	}
	// 注意：不要 close readyR！
	// xdg-dbus-proxy 监视此 fd 的 HUP/ERR：对端关闭 = 立即 unlink socket 并退出。
	// 读端必须由 cwrap 主进程持有到沙箱运行结束（见 Stop）。
	return pr, nil
}

// memfdArgs 把参数按 NUL 分隔写入 memfd 并回卷偏移（供 --args=FD 读取）。
// xdg-dbus-proxy 的 add_args() 按 NUL 分割、尾部 NUL 不产生空参数；
// cwrap 生成的参数（路径/总线名/规则）本身不含 NUL。
func memfdArgs(name string, lines []string) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, 0)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	f := os.NewFile(uintptr(fd), name)
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte(0)
	}
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// memfdBytes 把字节写入 memfd 并回卷偏移。
func memfdBytes(name string, data []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, 0)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	f := os.NewFile(uintptr(fd), name)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// dbusProxyWrapperArgs 生成包装代理所用 bwrap 的参数（对齐 flatpak
// add_bwrap_wrapper）：宿主根目录逐项挂入——tmp/var/run 保持读写，
// 其余目录只读，符号链接原样重建（宿主根上的普通文件不挂）；
// 代理 socket 所在目录读写（代理在其中创建并 unlink socket）；
// /.flatpak-info 以 --ro-bind-data（perms 0600）提供——flatpak 注释原话：
// "primary to allow the command to be run with a proper /.flatpak-info"。
//
// 生命周期同步（任一层生效即回收包装 bwrap 及其代理子进程）：
//  1. cwrap 死 → ready 管道读端关闭 → 代理收到 HUP → 代理自停并 unlink socket；
//  2. cwrap 死 → 包装 bwrap 收到 PDEATHSIG（--die-with-parent）→ bwrap 退出；
//  3. 代理卡死不响应 HUP → Stop 超时对进程组整组 SIGKILL（Setpgid 见 Start）。
func dbusProxyWrapperArgs(socketDir string, infoFD int) []string {
	var a []string
	a = append(a, "--die-with-parent")
	if entries, err := os.ReadDir("/"); err == nil {
		for _, e := range entries {
			name := e.Name()
			if name == ".flatpak-info" {
				continue
			}
			path := "/" + name
			switch {
			case name == "tmp" || name == "var" || name == "run":
				a = append(a, "--bind-try", path, path)
			case e.Type()&os.ModeSymlink != 0:
				if tgt, lerr := os.Readlink(path); lerr == nil {
					a = append(a, "--symlink", tgt, path)
				}
			case e.IsDir():
				a = append(a, "--ro-bind-try", path, path)
			}
		}
	}
	a = append(a, "--bind-try", socketDir, socketDir)
	a = append(a, "--perms", "0600",
		"--ro-bind-data", strconv.Itoa(infoFD), "/.flatpak-info")
	return a
}

// Stop 终止代理。先关闭 sync 读端触发 xdg-dbus-proxy 的
// 优雅退出（它会自行 unlink socket），超时再 SIGKILL。可重复调用。
func (p *Proxy) Stop() {
	if p == nil {
		return
	}
	if p.ready != nil {
		p.ready.Close()
		p.ready = nil
		done := make(chan struct{})
		go func() { p.cmd.Wait(); close(done) }()
		select {
		case <-done: // 代理收到 HUP，已自停并清理 socket
		case <-time.After(2 * time.Second):
			// 兜底：整组 SIGKILL。仅 Kill 包装 bwrap 会让代理（其子进程）
			// 变孤儿继续运行，socket 残留且进程仍活，pruneLocked 扫不到。
			if p.cmd.Process != nil {
				if pgid, gerr := syscall.Getpgid(p.cmd.Process.Pid); gerr == nil && pgid > 0 {
					syscall.Kill(-pgid, syscall.SIGKILL)
				} else {
					p.cmd.Process.Kill() // 取不到 pgid 时退回单进程
				}
			}
			<-done // 收尸交给 goroutine 里的 Wait，避免双 Wait 竞态
		}
		return
	}
	// ready 已空：要么从未成功启动，要么已 Stop 过，确保进程收尸即可
	if p.cmd != nil && p.cmd.Process != nil {
		p.cmd.Process.Kill()
		p.cmd.Wait()
	}
}
