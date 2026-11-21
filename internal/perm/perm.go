// Package perm 定义 cwrap 的权限模型。
//
// 语义对齐 Flatpak 与 bubblejail，但更直白：默认零权限，所有能力都
// 需要通过 FLAG 或 TOML 配置文件显式授予。
//
// 合并规则（全局配置 -> 应用配置 -> 命令行 FLAG）：
// 标量字段非空覆盖；列表字段累加并去除完全重复的值。
//
// 否决语义（对齐 flatpak override --nosocket 等）：任何列表项支持
// "!" 前缀（TOML 写 "!x11"，FLAG 提供 --no-share/--no-socket 等），
// 否决发生在最终合并结果上：被否决的值从列表中整体移除。
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
	ShareValues  = []string{"network", "ipc"}
	SocketValues = []string{
		"x11", "wayland", "pulseaudio", "pipewire", "cups", "pcsc", "ssh-agent",
		// 对齐 flatpak --socket 的直通逃生门与 gpg-agent
		"session-bus", "system-bus", "gpg-agent",
	}
	DeviceValues = []string{
		"dri", "kvm", "all",
		// 对齐 bubblejail joystick / v4l / ntsync 服务
		"input", "v4l", "ntsync",
	}
	AllowValues   = []string{"devel", "multiarch", "portal"} // portal: xdg-desktop-portal 权限包（bubblejail xdg_desktop_portal 服务）
	SeccompLevels = []string{"low", "medium", "high"}        // low 宽松 -> high 最严格
	FSModes       = []string{"ro", "rw"}
	DBusTargets   = []string{
		"session.talk", "session.own", "session.see", "session.call", "session.broadcast",
		"system.talk", "system.own", "system.see", "system.call", "system.broadcast",
	}
	// DBusPresetNames 是 --dbus preset:NAME 可用的预设（逐条对齐
	// bubblejail notify/systray/gamemode/mpris/xdg_desktop_portal/
	// gnome_toolkit/ibus/fcitx 服务的规则集）。
	DBusPresetNames = []string{
		"notify", "systray", "gamemode", "mpris", "portal",
		"gnome-toolkit", "ibus", "fcitx",
	}
	HardenValues = []string{"namespaces", "sync"}           // namespaces: 递归封死沙箱内建 ns；sync: 假装磁盘同步成功
	NetBackends  = []string{"host", "pasta", "slirp4netns"} // host: 共享宿主网络；其余为用户态网络栈（bubblejail pasta_network/slirp4netns 对齐）
	TmpKinds     = []string{"tmpfs", "host"}                // /tmp 处理方式
)

// Permissions 是一次沙箱运行的完整权限描述。
// 所有切片字段表示"授予列表"，空表示未授予。
type Permissions struct {
	App  string `toml:"app"`            // 应用名，决定 HOME 目录与配置文件（可省略）
	Home string `toml:"home,omitempty"` // 自定义沙箱 HOME 目录（默认 $HOME/.var/sandbox/<App>，无 App 时为 $HOME/.var/sandbox/home）

	Share   []string `toml:"share,omitempty"`   // network, ipc
	Socket  []string `toml:"socket,omitempty"`  // x11, wayland, pulseaudio, pipewire, cups, pcsc, ssh-agent, session-bus, system-bus, gpg-agent
	Device  []string `toml:"device,omitempty"`  // dri, kvm, all, input, v4l, ntsync
	Allow   []string `toml:"allow,omitempty"`   // devel, multiarch, portal
	FS      []string `toml:"fs,omitempty"`      // "ro:/path" 或 "rw:/path"
	Env     []string `toml:"env,omitempty"`     // "KEY=VALUE"
	DBus    []string `toml:"dbus,omitempty"`    // "session.talk=NAME" / "session.call=NAME=iface.method@path" / "preset:notify" 等
	Seccomp string   `toml:"seccomp,omitempty"` // low | medium | high
	Tmp     string   `toml:"tmp,omitempty"`     // tmpfs(默认) | host

	// 加固与网络后端（对齐 bubblejail namespaces_limits / pasta_network / slirp4netns）
	Harden         []string `toml:"harden,omitempty"`           // namespaces, sync
	NetBackend     string   `toml:"net_backend,omitempty"`      // host(默认) | pasta | slirp4netns
	NetBackendArgs []string `toml:"net_backend_args,omitempty"` // 传给 pasta/slirp4netns 的额外参数

	// 环境变量移除（对齐 flatpak --unset-env）
	UnsetEnv []string `toml:"unset_env,omitempty"`

	// 调试透传（对齐 bubblejail debug 服务的 raw_bwrap_args/raw_dbus_args）
	RawBwrap []string `toml:"raw_bwrap,omitempty"` // 原样追加到 bwrap 参数
	RawDBus  []string `toml:"raw_dbus,omitempty"`  // 原样追加到 xdg-dbus-proxy 参数

	// 追加白名单 syscall（与等级集合叠加）
	AllowSyscalls []string `toml:"allow_syscalls,omitempty"` // 追加白名单 syscall
}

// Overlay 把 other 的权限叠加到 p 上（标量非空覆盖，列表累加去重，
// 不处理否决项——由 ApplyDenies 统一处理）。
func (p *Permissions) Overlay(other *Permissions) {
	if other == nil {
		return
	}
	if other.App != "" {
		p.App = other.App
	}
	if other.Home != "" {
		p.Home = other.Home
	}
	if other.Seccomp != "" {
		p.Seccomp = other.Seccomp
	}
	if other.Tmp != "" {
		p.Tmp = other.Tmp
	}
	if other.NetBackend != "" {
		p.NetBackend = other.NetBackend
	}
	p.Share = OverlayList(p.Share, other.Share)
	p.Socket = OverlayList(p.Socket, other.Socket)
	p.Device = OverlayList(p.Device, other.Device)
	p.Allow = OverlayList(p.Allow, other.Allow)
	p.FS = OverlayList(p.FS, other.FS)
	p.DBus = OverlayList(p.DBus, other.DBus)
	p.Env = OverlayList(p.Env, other.Env)
	p.AllowSyscalls = OverlayList(p.AllowSyscalls, other.AllowSyscalls)
	p.Harden = OverlayList(p.Harden, other.Harden)
	p.NetBackendArgs = OverlayList(p.NetBackendArgs, other.NetBackendArgs)
	p.UnsetEnv = OverlayList(p.UnsetEnv, other.UnsetEnv)
	p.RawBwrap = OverlayList(p.RawBwrap, other.RawBwrap)
	p.RawDBus = OverlayList(p.RawDBus, other.RawDBus)
}

// Default 返回一份默认零权限的空权限描述。
func Default() *Permissions { return &Permissions{} }

// ---------- 否决语义 ----------

// denyPrefix 标记列表中的否决项（"!value"）。
const denyPrefix = "!"

// ApplyDenies 处理全部列表字段的否决项：从最终合并结果中移除被否决的
// 值（或精确 token），并删除否决标记本身。对齐 flatpak override 的
// --nosocket/--nofilesystem 等收窄语义。
func (p *Permissions) ApplyDenies() {
	p.Share = applyDeny(p.Share)
	p.Socket = applyDeny(p.Socket)
	p.Device = applyDeny(p.Device)
	p.Allow = applyDeny(p.Allow)
	p.FS = applyDeny(p.FS)
	p.Env = applyDeny(p.Env)
	p.DBus = applyDeny(p.DBus)
	p.AllowSyscalls = applyDeny(p.AllowSyscalls)
	p.Harden = applyDeny(p.Harden)
	p.NetBackendArgs = applyDeny(p.NetBackendArgs)
	p.UnsetEnv = applyDeny(p.UnsetEnv)
	p.RawBwrap = applyDeny(p.RawBwrap)
	p.RawDBus = applyDeny(p.RawDBus)
}

// applyDeny 返回移除否决项后的列表。
// 规则：收集所有 "!X"，然后从列表中同时移除 "!X" 标记与精确匹配的 X。
func applyDeny(list []string) []string {
	if len(list) == 0 {
		return list
	}
	denied := make(map[string]struct{})
	kept := make([]string, 0, len(list))
	for _, v := range list {
		if strings.HasPrefix(v, denyPrefix) && len(v) > len(denyPrefix) {
			denied[v[len(denyPrefix):]] = struct{}{}
			continue
		}
		kept = append(kept, v)
	}
	if len(denied) == 0 {
		return kept
	}
	out := make([]string, 0, len(kept))
	for _, v := range kept {
		if _, bad := denied[v]; bad {
			continue
		}
		out = append(out, v)
	}
	return Dedupe(out)
}

// ---------- 合并 ----------

// OverlayList 累加两个列表并去除完全重复的值（保持首次出现的顺序）。
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

// Has 判断列表是否包含某值。
func Has(list []string, v string) bool { return inList(list, v) }

// ---------- 便捷判定 ----------

// ShareNet 返回是否共享宿主网络。
func (p *Permissions) ShareNet() bool {
	if p.NetBackend != "" && p.NetBackend != "host" {
		return false // 用户态网络后端下必然与宿主隔离
	}
	return inList(p.Share, "network")
}

// ShareIPC 返回是否共享宿主 IPC。
func (p *Permissions) ShareIPC() bool { return inList(p.Share, "ipc") }

// Sock 返回是否授予某类 socket。
func (p *Permissions) Sock(name string) bool { return inList(p.Socket, name) }

// Dev 返回是否授予某类设备。
func (p *Permissions) Dev(name string) bool { return inList(p.Device, name) }

// AllowDevel 返回是否授予 devel（放宽 W^X）。
func (p *Permissions) AllowDevel() bool { return inList(p.Allow, "devel") }

// AllowPortal 返回是否授予 portal 权限包。
func (p *Permissions) AllowPortal() bool { return inList(p.Allow, "portal") }

// Hardened 返回是否开启某项加固。
func (p *Permissions) Hardened(name string) bool { return inList(p.Harden, name) }

// UserNetBackend 返回网络后端（默认 host）。
func (p *Permissions) UserNetBackend() string {
	if p.NetBackend == "" {
		return "host"
	}
	return p.NetBackend
}

// DbusTokens 返回展开预设后的 D-Bus 规则 token 列表。
// preset:notify -> notify 预设规则；preset:mpris=GLOB -> mpris 自有名。
func (p *Permissions) DbusTokens() ([]string, error) {
	return ExpandDbusPresets(p.DBus)
}

// UsedPresets 返回 DBus 列表中使用的预设名（未展开）。
func UsedPresets(tokens []string) []string {
	var out []string
	for _, tok := range tokens {
		if strings.HasPrefix(tok, "preset:") {
			name, _, _ := strings.Cut(strings.TrimPrefix(tok, "preset:"), "=")
			out = append(out, name)
		}
	}
	return out
}

// ---------- D-Bus 规则与预设 ----------

// DbusRule 解析后的 D-Bus 授权规则。
type DbusRule struct {
	Target string // session.talk | session.own | session.see | session.call | session.broadcast | system.*
	Name   string // 总线名或规则值（call/broadcast 为 name=iface.method@path）
}

// DbusRules 解析 DBus 字段（含预设展开），返回结构化规则。
func (p *Permissions) DbusRules() ([]DbusRule, error) {
	tokens, err := p.DbusTokens()
	if err != nil {
		return nil, err
	}
	var rules []DbusRule
	for _, tok := range tokens {
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

// ExpandDbusPresets 展开 DBus 列表中的 preset: 项，其余原样保留。
// 预设规则集逐条对齐 bubblejail 对应服务（services.py）：
//
//	notify         talk Notifications + call org.freedesktop.Notifications.*@/org/freedesktop/Notifications
//	systray        talk org.kde.StatusNotifierWatcher + call ...@/StatusNotifierWatcher
//	gamemode       talk com.feralinteractive.GameMode + call ...@/com/feralinteractive/GameMode
//	mpris=GLOB     own org.mpris.MediaPlayer2.<GLOB>
//	portal         talk org.freedesktop.portal.Desktop + Properties/Request/Session/interface 调用规则
//	gnome-toolkit  talk portal.* + ca.desrt.dconf + org.gtk.vfs.*
//	ibus           talk org.freedesktop.portal.IBus
//	fcitx          talk org.freedesktop.portal.Fcitx
func ExpandDbusPresets(tokens []string) ([]string, error) {
	var out []string
	for _, tok := range tokens {
		if !strings.HasPrefix(tok, "preset:") {
			out = append(out, tok)
			continue
		}
		spec := strings.TrimPrefix(tok, "preset:")
		name, arg, _ := strings.Cut(spec, "=")
		switch name {
		case "notify":
			out = append(out,
				"session.talk=org.freedesktop.Notifications",
				"session.call=org.freedesktop.Notifications=org.freedesktop.Notifications.*@/org/freedesktop/Notifications",
			)
		case "systray":
			out = append(out,
				"session.talk=org.kde.StatusNotifierWatcher",
				"session.call=org.kde.StatusNotifierWatcher=org.kde.StatusNotifierWatcher.*@/StatusNotifierWatcher",
			)
		case "gamemode":
			out = append(out,
				"session.talk=com.feralinteractive.GameMode",
				"session.call=com.feralinteractive.GameMode=com.feralinteractive.GameMode.*@/com/feralinteractive/GameMode",
			)
		case "mpris":
			glob := arg
			if glob == "" {
				return nil, fmt.Errorf("preset:mpris 需要播放器名 glob（如 preset:mpris=firefox.*）")
			}
			out = append(out, "session.own=org.mpris.MediaPlayer2."+glob)
		case "portal":
			// 对齐 bubblejail xdg_desktop_portal 服务：基座 + Request/Session 回执
			out = append(out,
				"session.talk=org.freedesktop.portal.Desktop",
				"session.call=org.freedesktop.portal.Desktop=org.freedesktop.DBus.Properties.*@/org/freedesktop/portal/desktop",
				"session.call=org.freedesktop.portal.Desktop=org.freedesktop.portal.*@/org/freedesktop/portal/desktop",
				"session.call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Request.*@/org/freedesktop/portal/desktop/request/*",
				"session.call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Session.*@/org/freedesktop/portal/desktop/session/*",
			)
		case "gnome-toolkit":
			out = append(out,
				"session.talk=org.freedesktop.portal.*",
				"session.talk=ca.desrt.dconf",
				"session.talk=org.gtk.vfs.*",
			)
		case "ibus":
			out = append(out, "session.talk=org.freedesktop.portal.IBus")
		case "fcitx":
			out = append(out, "session.talk=org.freedesktop.portal.Fcitx")
		default:
			return nil, fmt.Errorf("未知 --dbus 预设 %q（可选：%s）", name, strings.Join(DBusPresetNames, ","))
		}
	}
	return Dedupe(out), nil
}

// ---------- FS 规则 ----------

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

// ---------- 校验 ----------

// Validate 校验整份权限描述。
func (p *Permissions) Validate() error {
	// 否决项在校验前结算（含配置文件内的 "!" 前缀写法）
	p.ApplyDenies()

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
		{"--harden", HardenValues, p.Harden},
	} {
		for _, v := range group.list {
			if !inList(group.values, v) {
				return fmt.Errorf("无效的 %s 值 %q（可选：%s）", group.name, v, strings.Join(group.values, ","))
			}
		}
	}
	if p.NetBackend != "" && !inList(NetBackends, p.NetBackend) {
		return fmt.Errorf("无效的 --net-backend %q（可选：%s）", p.NetBackend, strings.Join(NetBackends, ","))
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
		home = p.HomeDirHost() + "（默认）"
	}
	fmt.Fprintf(&b, "home     = %s\n", home)
	fmt.Fprintf(&b, "seccomp  = %s\n", DefaultSeccomp(p.Seccomp))
	fmt.Fprintf(&b, "tmp      = %s\n", DefaultTmpIfEmpty(p.Tmp))
	nb := p.UserNetBackend()
	if len(p.NetBackendArgs) > 0 {
		fmt.Fprintf(&b, "net      = %s（args: %s）\n", nb, strings.Join(p.NetBackendArgs, ","))
	} else {
		fmt.Fprintf(&b, "net      = %s\n", nb)
	}
	extra := []string{}
	if len(p.AllowSyscalls) > 0 {
		extra = append(extra, "syscall:"+strings.Join(p.AllowSyscalls, ","))
	}
	if len(p.Harden) > 0 {
		extra = append(extra, "harden:"+strings.Join(p.Harden, ","))
	}
	if len(extra) > 0 {
		fmt.Fprintf(&b, "extra    = %s\n", strings.Join(extra, ","))
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
	show("unset-env", p.UnsetEnv)
	show("raw-bwrap", p.RawBwrap)
	show("raw-dbus", p.RawDBus)
	return b.String()
}

// DefaultTmpIfEmpty 返回 tmp 值（空回退默认）。
func DefaultTmpIfEmpty(v string) string {
	if v == "" {
		return DefaultTmp()
	}
	return v
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
//	tmpfs          （默认）全空的 --tmpfs /tmp
//	host           完整访问宿主 /tmp（--bind /tmp /tmp）
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
