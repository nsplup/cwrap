// Package perm 定义 cwrap 的权限模型。
//
// 语义对齐 Flatpak，但更直白：默认零权限，所有能力都需要通过
// FLAG 或 TOML 配置文件显式授予。
//
// 合并规则（全局配置 -> 应用配置 -> 命令行 FLAG）：
// 标量字段非空覆盖；列表字段累加并去除完全重复的值。
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
        TmpKinds      = []string{"tmpfs", "host"} // /tmp 处理方式
)

// Permissions 是一次沙箱运行的完整权限描述。
// 所有切片字段表示"授予列表"，空表示未授予。
type Permissions struct {
        App  string `toml:"app"`            // 应用名，决定 HOME 目录与配置文件（可省略）
        Home string `toml:"home,omitempty"` // 自定义沙箱 HOME 目录（默认 $HOME/.var/sandbox/<App>，无 App 时为 $HOME/.var/sandbox/home）

        Share   []string `toml:"share,omitempty"`   // network, ipc
        Socket  []string `toml:"socket,omitempty"`  // x11, wayland, pulseaudio, pipewire, cups, pcsc, ssh-agent
        Device  []string `toml:"device,omitempty"`  // dri, kvm, all
        Allow   []string `toml:"allow,omitempty"`   // devel, multiarch
        FS      []string `toml:"fs,omitempty"`      // "ro:/path" 或 "rw:/path"
        Env     []string `toml:"env,omitempty"`     // "KEY=VALUE"
        DBus    []string `toml:"dbus,omitempty"`    // "session.talk=NAME" 等
        Seccomp string   `toml:"seccomp,omitempty"` // low | medium | high
        Tmp     string   `toml:"tmp,omitempty"`     // tmpfs(默认) | host

        AllowSyscalls []string `toml:"allow_syscalls,omitempty"` // 追加的 syscall 白名单
}

// Default 返回默认权限：seccomp=medium（对齐 flatpak 默认），
// /tmp 使用全空 tmpfs，其余全部关闭。
func Default() *Permissions {
        return &Permissions{Seccomp: "medium", Tmp: "tmpfs"}
}

// Overlay 把 src 中非空字段合并到 dst（用于 全局配置 -> 应用配置 -> FLAG 的合并）。
// 标量字段：非空覆盖；列表字段：累加并去除完全重复的值。
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
        if src.Tmp != "" {
                p.Tmp = src.Tmp
        }
        p.Share = OverlayList(p.Share, src.Share)
        p.Socket = OverlayList(p.Socket, src.Socket)
        p.Device = OverlayList(p.Device, src.Device)
        p.Allow = OverlayList(p.Allow, src.Allow)
        p.FS = OverlayList(p.FS, src.FS)
        p.Env = OverlayList(p.Env, src.Env)
        p.DBus = OverlayList(p.DBus, src.DBus)
        p.AllowSyscalls = OverlayList(p.AllowSyscalls, src.AllowSyscalls)
}

// OverlayList 合并两份授予列表：累加后仅去除完全重复的值，保持原有顺序。
func OverlayList(base, overlay []string) []string {
        if len(overlay) == 0 {
                return Dedupe(base)
        }
        merged := make([]string, 0, len(base)+len(overlay))
        merged = append(merged, base...)
        merged = append(merged, overlay...)
        return Dedupe(merged)
}

// Dedupe 去除列表中完全重复的值，保持首次出现的顺序。
func Dedupe(list []string) []string {
        if len(list) == 0 {
                return list
        }
        seen := make(map[string]struct{}, len(list))
        out := make([]string, 0, len(list))
        for _, v := range list {
                if _, ok := seen[v]; ok {
                        continue
                }
                seen[v] = struct{}{}
                out = append(out, v)
        }
        return out
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

// FSRules 解析 FS 字段（"ro:/path" / "rw:/path"）。PATH 支持绝对路径与
// flatpak 风格关键字（见 fskeys.go），尾缀 ? 表示路径不存在不报错。
func (p *Permissions) FSRules() ([]FSRule, error) {
        var rules []FSRule
        for _, tok := range p.FS {
                mode, path, err := ParseFS(tok)
                if err != nil {
                        return nil, err
                }
                rules = append(rules, FSRule{Mode: mode, Path: path})
        }
        return rules, nil
}

// Validate 校验整份权限描述。
func (p *Permissions) Validate() error {
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
        if p.Tmp == "" {
                p.Tmp = "tmpfs"
        }
        if _, err := ParseTmp(p.Tmp); err != nil {
                return err
        }
        if _, err := p.DbusRules(); err != nil {
                return err
        }
        return nil
}

// HomeDirHost 返回宿主侧沙箱 HOME 目录（默认 $HOME/.var/sandbox/<App>；
// 未指定应用名时使用 $HOME/.var/sandbox/home）。
func (p *Permissions) HomeDirHost() string {
        if p.Home != "" {
                return p.Home
        }
        name := p.App
        if name == "" {
                name = "home"
        }
        base, err := os.UserHomeDir()
        if err != nil || base == "" {
                base = "/tmp"
        }
        return filepath.Join(base, ".var", "sandbox", name)
}

// Describe 生成人类可读的权限摘要（permission show 用）。
func (p *Permissions) Describe() string {
        var b strings.Builder
        fmt.Fprintf(&b, "app      = %s\n", p.App)
        home := p.Home
        if home == "" {
                name := p.App
                if name == "" {
                        name = "home"
                }
                home = fmt.Sprintf("$HOME/.var/sandbox/%s (默认)", name)
        }
        fmt.Fprintf(&b, "home     = %s\n", home)
        fmt.Fprintf(&b, "seccomp  = %s\n", p.Seccomp)
        fmt.Fprintf(&b, "tmp      = %s\n", p.Tmp)
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

// ParseFS 解析 "ro:PATH" / "rw:PATH" 形式的文件系统授权项。
// PATH 支持绝对路径与 flatpak 关键字（home、host、xdg-*、~/... 等），
// 尾缀 ? 表示目标不存在不报错。
func ParseFS(spec string) (mode, path string, err error) {
        mode, path, found := strings.Cut(spec, ":")
        if !found {
                return "", "", fmt.Errorf("无效的 --fs 项 %q（应为 ro:PATH 或 rw:PATH）", spec)
        }
        if !inList(FSModes, mode) {
                return "", "", fmt.Errorf("无效的 --fs 模式 %q（可选：ro、rw）", mode)
        }
        if err := FSPathValid(path); err != nil {
                return "", "", err
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

// DefaultTmp 返回 /tmp 处理方式的默认值。
func DefaultTmp() string { return "tmpfs" }

// TmpSetting 是解析后的 --tmp 设置。
type TmpSetting struct {
        Kind string // tmpfs | host
}

// ParseTmp 解析 --tmp 参数值：
//
//      tmpfs          （默认）全空的 --tmpfs /tmp
//      host           完整访问宿主 /tmp（--bind /tmp /tmp）
func ParseTmp(v string) (*TmpSetting, error) {
        if v == "" {
                v = DefaultTmp()
        }
        switch v {
        case "tmpfs", "host":
                return &TmpSetting{Kind: v}, nil
        }
        return nil, fmt.Errorf("无效的 --tmp 值 %q（可选：tmpfs | host）", v)
}

// FilterTmpFSConflicts 检查 FS 授权与 --tmp 提供的 /tmp 的重叠，
// 返回过滤后的 FS 列表与警告文案。
//
// 规则：
//   - 任何模式下，--fs 指向 /tmp 本身都会与 --tmp 挂载冲突 → 过滤 + 警告；
//   - tmp=host 时（宿主 /tmp 整体可访问），/tmp 下的子路径已被覆盖
//     （且 ro 收窄会失效）→ 过滤 + 警告；
//   - tmpfs 模式下 /tmp 子路径仍可挂载进空 tmpfs，保留不动。
func FilterTmpFSConflicts(p *Permissions) (fs []string, warnings []string) {
        ts, err := ParseTmp(p.Tmp)
        if err != nil {
                return p.FS, nil // 校验错误由 Validate 负责
        }
        hostTmpExposed := ts.Kind == "host"
        var kept []string
        for _, tok := range p.FS {
                _, path, err := ParseFS(tok)
                if err != nil {
                        kept = append(kept, tok) // 语法错误留给 Validate 报
                        continue
                }
                resolved, _, err := ResolveFSPath(path)
                if err != nil {
                        kept = append(kept, tok)
                        continue
                }
                conflict := ""
                for _, r := range resolved {
                        if r == "/tmp" {
                                conflict = r
                                break
                        }
                        if hostTmpExposed && strings.HasPrefix(r, "/tmp/") {
                                conflict = r
                                break
                        }
                }
                if conflict == "" {
                        kept = append(kept, tok)
                        continue
                }
                warnings = append(warnings, fmt.Sprintf(
                        "警告: --fs %s 的挂载点 %s 已由 --tmp %s 提供的 /tmp 覆盖，该项已被忽略；"+
                                "如需指定 /tmp 内容请使用 --tmp 参数（如 --tmp host）",
                        tok, conflict, p.Tmp))
        }
        return kept, warnings
}
