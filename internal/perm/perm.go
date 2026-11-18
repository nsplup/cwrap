// Package perm 定义 cwrap 的权限模型。
//
// 语义对齐 Flatpak，但更直白：默认零权限，所有能力都需要通过
// FLAG 或 TOML 配置文件显式授予。
package perm

import (
        "fmt"
        "os"
        "path/filepath"
        "sort"
        "strings"
)

// 可选值集合（校验用）。
var (
        ShareValues   = []string{"network", "ipc"}
        SocketValues  = []string{"x11", "wayland", "pulseaudio", "pipewire", "cups", "pcsc", "ssh-agent"}
        DeviceValues  = []string{"dri", "kvm", "all"}
        AllowValues   = []string{"devel", "multiarch"}
        SeccompLevels = []string{"low", "medium", "high"} // low 宽松 -> high 最严格
        FSModes       = []string{"ro", "rw"}
        DBusTargets   = []string{"session.talk", "session.own", "system.talk", "system.own"}
)

// Permissions 是一次沙箱运行的完整权限描述。
// 所有切片字段表示"授予列表"，空表示未授予。
type Permissions struct {
        App  string `toml:"app"`            // 应用名，决定 HOME 目录与配置文件
        Home string `toml:"home,omitempty"` // 自定义沙箱 HOME 目录（默认 $HOME/.var/sandbox/<App>）

        Share   []string `toml:"share,omitempty"`   // network, ipc
        Socket  []string `toml:"socket,omitempty"`  // x11, wayland, pulseaudio, pipewire, cups, pcsc, ssh-agent
        Device  []string `toml:"device,omitempty"`  // dri, kvm, all
        Allow   []string `toml:"allow,omitempty"`   // devel, multiarch
        FS      []string `toml:"fs,omitempty"`      // "ro:/path" 或 "rw:/path"
        Env     []string `toml:"env,omitempty"`     // "KEY=VALUE"
        EnvAdd  []string `toml:"-"`                 // 仅 FLAG：追加透传的环境变量
        DBus    []string `toml:"dbus,omitempty"`    // "session.talk=NAME" 等
        Seccomp string   `toml:"seccomp,omitempty"` // low | medium | high

        AllowSyscalls []string `toml:"allow_syscalls,omitempty"` // 追加的 syscall 白名单
}

// Default 返回默认权限：seccomp=medium（对齐 flatpak 默认），其余全部关闭。
func Default() *Permissions {
        return &Permissions{Seccomp: "medium"}
}

// Overlay 把 src 中非空字段覆盖到 dst（用于 全局配置 -> 应用配置 -> FLAG 的合并）。
func (p *Permissions) Overlay(src *Permissions) {
        if src == nil {
                return
        }
        if src.App != "" {
                p.App = src.App
        }
        if src.Home != "" {
                p.Home = src.Home
        }
        if src.Seccomp != "" {
                p.Seccomp = src.Seccomp
        }
        p.Share = overlayList(p.Share, src.Share)
        p.Socket = overlayList(p.Socket, src.Socket)
        p.Device = overlayList(p.Device, src.Device)
        p.Allow = overlayList(p.Allow, src.Allow)
        p.FS = overlayList(p.FS, src.FS)
        p.Env = overlayList(p.Env, src.Env)
        p.DBus = overlayList(p.DBus, src.DBus)
        p.AllowSyscalls = overlayList(p.AllowSyscalls, src.AllowSyscalls)
        p.EnvAdd = overlayList(p.EnvAdd, src.EnvAdd)
}

func overlayList(base, overlay []string) []string {
        if len(overlay) == 0 {
                return base
        }
        return overlay
}

func inList(list []string, v string) bool {
        for _, x := range list {
                if x == v {
                        return true
                }
        }
        return false
}

// Has 在授予列表 list 中查找 v（逗号分隔的 FLAG 已在解析阶段拆开）。
func Has(list []string, v string) bool { return inList(list, v) }

// ShareNet 返回是否共享宿主网络。
func (p *Permissions) ShareNet() bool { return inList(p.Share, "network") }

// ShareIPC 返回是否共享宿主 IPC。
func (p *Permissions) ShareIPC() bool { return inList(p.Share, "ipc") }

// Sock 返回是否授予某类 socket。
func (p *Permissions) Sock(name string) bool { return inList(p.Socket, name) }

// Dev 返回是否授予某类设备。
func (p *Permissions) Dev(name string) bool { return inList(p.Device, name) }

// AllowDevel 返回是否授予 devel（放宽 W^X）。
func (p *Permissions) AllowDevel() bool { return inList(p.Allow, "devel") }

// DbusRule 解析后的 D-Bus 授权规则。
type DbusRule struct {
        Target string // session.talk | session.own | system.talk | system.own
        Name   string // 总线名
}

// DbusRules 解析 DBus 字段（"session.talk=org.example"）。
func (p *Permissions) DbusRules() ([]DbusRule, error) {
        var rules []DbusRule
        for _, tok := range p.DBus {
                idx := strings.Index(tok, "=")
                if idx < 0 {
                        return nil, fmt.Errorf("无效的 --dbus 项 %q，期望格式 target=NAME（target ∈ %s）", tok, strings.Join(DBusTargets, "|"))
                }
                target, name := tok[:idx], tok[idx+1:]
                if !inList(DBusTargets, target) {
                        return nil, fmt.Errorf("无效的 --dbus target %q（可选：%s）", target, strings.Join(DBusTargets, "|"))
                }
                if name == "" {
                        return nil, fmt.Errorf("--dbus %s 的总线名不能为空", target)
                }
                rules = append(rules, DbusRule{Target: target, Name: name})
        }
        return rules, nil
}

// FSRule 解析后的文件系统授权。
type FSRule struct {
        Mode string // ro | rw
        Path string
}

// FSRules 解析 FS 字段（"ro:/path" / "rw:/path"）。
func (p *Permissions) FSRules() ([]FSRule, error) {
        var rules []FSRule
        for _, tok := range p.FS {
                idx := strings.Index(tok, ":")
                if idx < 0 {
                        return nil, fmt.Errorf("无效的 --fs 项 %q，期望格式 ro:PATH 或 rw:PATH", tok)
                }
                mode, path := tok[:idx], tok[idx+1:]
                if !inList(FSModes, mode) {
                        return nil, fmt.Errorf("无效的 --fs 模式 %q（可选：ro、rw）", mode)
                }
                if !strings.HasPrefix(path, "/") {
                        return nil, fmt.Errorf("--fs 路径必须是绝对路径：%q", tok)
                }
                if path == "/" {
                        return nil, fmt.Errorf("--fs 不允许挂载宿主根目录 /（如需完整宿主请使用 --fs rw:/path 逐项授权）")
                }
                rules = append(rules, FSRule{Mode: mode, Path: path})
        }
        return rules, nil
}

// Validate 校验整份权限描述。
func (p *Permissions) Validate() error {
        if p.App == "" {
                return fmt.Errorf("缺少应用名：请通过 --app 或配置文件指定")
        }
        if p.Seccomp == "" {
                p.Seccomp = "medium"
        }
        if !inList(SeccompLevels, p.Seccomp) && p.Seccomp != "off" {
                return fmt.Errorf("无效的 --seccomp 等级 %q（可选：low|medium|high|off）", p.Seccomp)
        }
        for _, group := range []struct {
                name   string
                values []string
                list   []string
        }{
                {"--share", ShareValues, p.Share},
                {"--socket", SocketValues, p.Socket},
                {"--device", DeviceValues, p.Device},
                {"--allow", AllowValues, p.Allow},
        } {
                for _, v := range group.list {
                        if !inList(group.values, v) {
                                return fmt.Errorf("无效的 %s 值 %q（可选：%s）", group.name, v, strings.Join(group.values, ","))
                        }
                }
        }
        if _, err := p.FSRules(); err != nil {
                return err
        }
        if _, err := p.DbusRules(); err != nil {
                return err
        }
        return nil
}

// HomeDirHost 返回宿主侧沙箱 HOME 目录（默认 $HOME/.var/sandbox/<App>）。
func (p *Permissions) HomeDirHost() string {
        if p.Home != "" {
                return p.Home
        }
        base, err := os.UserHomeDir()
        if err != nil || base == "" {
                base = "/tmp"
        }
        return filepath.Join(base, ".var", "sandbox", p.App)
}

// Describe 生成人类可读的权限摘要（permission show 用）。
func (p *Permissions) Describe() string {
        var b strings.Builder
        fmt.Fprintf(&b, "app      = %s\n", p.App)
        home := p.Home
        if home == "" {
                home = fmt.Sprintf("$HOME/.var/sandbox/%s (默认)", p.App)
        }
        fmt.Fprintf(&b, "home     = %s\n", home)
        fmt.Fprintf(&b, "seccomp  = %s\n", p.Seccomp)
        if len(p.AllowSyscalls) > 0 {
                extra := append([]string(nil), p.AllowSyscalls...)
                sort.Strings(extra)
                fmt.Fprintf(&b, "syscalls += %s\n", strings.Join(extra, ","))
        }
        show := func(label string, list []string) {
                if len(list) > 0 {
                        s := append([]string(nil), list...)
                        sort.Strings(s)
                        fmt.Fprintf(&b, "%-9s= %s\n", label, strings.Join(s, ","))
                } else {
                        fmt.Fprintf(&b, "%-9s= (无)\n", label)
                }
        }
        show("share", p.Share)
        show("socket", p.Socket)
        show("device", p.Device)
        show("allow", p.Allow)
        show("fs", p.FS)
        show("dbus", p.DBus)
        show("env", p.Env)
        return b.String()
}

// ParseFS 解析 "ro:/path" / "rw:/path" 形式的文件系统授权项。
func ParseFS(spec string) (mode, path string, err error) {
        mode, path, found := strings.Cut(spec, ":")
        if !found {
                return "", "", fmt.Errorf("无效的 --fs 项 %q（应为 ro:/path 或 rw:/path）", spec)
        }
        if !inList(FSModes, mode) {
                return "", "", fmt.Errorf("无效的 --fs 模式 %q（可选：ro、rw）", mode)
        }
        if !strings.HasPrefix(path, "/") {
                return "", "", fmt.Errorf("--fs 路径必须是绝对路径：%q", spec)
        }
        if path == "/" {
                return "", "", fmt.Errorf("--fs 不允许挂载宿主根目录 /（如需完整宿主请使用 --fs rw:/path 逐项授权）")
        }
        return mode, path, nil
}

// DefaultSeccomp 返回合法的 seccomp 等级；空/未知值回退默认 medium。
// "off"（显式关闭过滤）为合法值，原样保留。
func DefaultSeccomp(v string) string {
        if v == "off" {
                return v
        }
        if inList(SeccompLevels, v) {
                return v
        }
        return "medium"
}
