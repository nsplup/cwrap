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
	"strings"
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
	ready *os.File // sync 管道读端：由 daemon 持有到代理退出，绝不提前关闭
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
func Start(proxyPath, addr, socketPath string, rules []string, logw io.Writer) (*Proxy, error) {
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
	// fd 3 = ready 同步管道；fd 4 = 参数文件（--args=4）
	argsContent := append([]string{addr, socketPath, "--filter"}, mapped...)
	argsFile, err := memfdLines("cwrap-dbus-proxy-args", argsContent)
	if err != nil {
		readyR.Close()
		readyW.Close()
		return nil, err
	}
	if proxyPath == "" {
		proxyPath = config.DefaultDBusProxyCmd
	}
	cmd := exec.Command(proxyPath, "--fd=3", "--args=4")
	cmd.ExtraFiles = []*os.File{readyW, argsFile}
	cmd.Stdout = logw
	cmd.Stderr = logw
	if err := cmd.Start(); err != nil {
		readyR.Close()
		readyW.Close()
		argsFile.Close()
		return nil, fmt.Errorf("启动 xdg-dbus-proxy（%s）: %w", proxyPath, err)
	}
	readyW.Close() // 父进程侧立刻关闭写端
	argsFile.Close()

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
	// 读端必须由 daemon 持有到沙箱运行结束（见 Stop）。
	return pr, nil
}

// memfdLines 把参数逐行写入 memfd 并回卷偏移（供 --args=FD 读取）。
// 参数本身不含换行时每行恰好一个参数；cwrap 生成的参数（路径/总线名/
// 规则）均不含换行。
func memfdLines(name string, lines []string) (*os.File, error) {
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
		case <-time.After(2 * time.Second): // 兜底：SIGKILL（socket 残留由 cleanStale 兜底）
			if p.cmd.Process != nil {
				p.cmd.Process.Kill()
			}
			p.cmd.Wait()
		}
		return
	}
	// ready 已空：要么从未成功启动，要么已 Stop 过，确保进程收尸即可
	if p.cmd != nil && p.cmd.Process != nil {
		p.cmd.Process.Kill()
		p.cmd.Wait()
	}
}

// SocketDir 为一次运行创建 socket 存放目录，返回路径与唯一 ID。
func SocketDir(runtimeDir string) (dir, id string, err error) {
	id = fmt.Sprintf("%d", time.Now().UnixNano())
	dir = filepath.Join(runtimeDir, "cwrap", id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	// 记录 daemon pid，供陈旧目录清扫判断存活
	if err := os.WriteFile(filepath.Join(dir, ".pid"), fmt.Append(nil, os.Getpid()), 0o600); err != nil {
		return "", "", err
	}
	return dir, id, nil
}
