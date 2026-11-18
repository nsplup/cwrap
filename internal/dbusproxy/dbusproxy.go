// Package dbusproxy 封装 xdg-dbus-proxy。
//
// 默认零放行：只有提供了显式的 talk/own 规则才会被加入白名单；
// 未请求任何 D-Bus 权限时不启动代理。
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
func NeedBuses(p *perm.Permissions) (session, system bool) {
	for _, d := range p.DBus {
		switch {
		case strings.HasPrefix(d, "session."):
			session = true
		case strings.HasPrefix(d, "system."):
			system = true
		}
	}
	return
}

// Start 启动代理并等待就绪。
//
// addr/socketPath 为总线地址与 socket 输出路径；readyFD 通过 ExtraFiles
// 传入（固定为子进程 fd 3），代理就绪后向其写一个字节。
func Start(addr, socketPath string, rules []string, logw io.Writer) (*Proxy, error) {
	readyR, readyW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	args := []string{"--fd=3", addr, socketPath, "--filter"}
	for _, r := range rules {
		tgt, name, ok := strings.Cut(r, "=")
		if !ok || name == "" {
			readyR.Close()
			readyW.Close()
			return nil, fmt.Errorf("非法 --dbus 规则 %q（应为 session.talk=NAME 等）", r)
		}
		switch tgt {
		case "session.talk", "system.talk":
			args = append(args, "--talk="+name)
		case "session.own", "system.own":
			args = append(args, "--own="+name)
		default:
			readyR.Close()
			readyW.Close()
			return nil, fmt.Errorf("非法 --dbus 目标 %q（可用: %s）", tgt, strings.Join(perm.DBusTargets, ","))
		}
	}

	cmd := exec.Command("xdg-dbus-proxy", args...)
	cmd.ExtraFiles = []*os.File{readyW}
	cmd.Stdout = logw
	cmd.Stderr = logw
	if err := cmd.Start(); err != nil {
		readyR.Close()
		readyW.Close()
		return nil, fmt.Errorf("启动 xdg-dbus-proxy: %w", err)
	}
	readyW.Close() // 父进程侧立刻关闭写端

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
