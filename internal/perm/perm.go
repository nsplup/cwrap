// Package perm 定义 cwrap 的权限模型。
//
// 语义对齐 Flatpak 与 bubblejail，但更直白：默认零权限，所有能力都
// 需要通过 FLAG 或 TOML 配置文件显式授予。
//
// 合并规则（全局配置 -> 应用配置 -> 命令行 FLAG）：
// 标量字段非空覆盖；列表字段累加并去除完全重复的值。
//
// 否决语义（对齐 flatpak override --nosocket 等）：列表项支持 "!" 前缀
// （TOML 写 "!x11"，FLAG 提供 --no-share/--no-socket 等），否决发生在
// 合并结果上：被否决的值从列表中整体移除。
//
// 优先级：否决与授权按所在层比较，高优先级层（后合并的层）的表态覆盖
// 低优先级层——高优先级授权可撤销低优先级否决（如全局 device=["!dri"]
// 被应用配置 device=["dri"] 覆盖为授予），高优先级否决也可收窄低优先级
// 授权。同一层内否决优先于授权（后项覆盖前项，最终由 ApplyDenies 结算）。
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

// Overlay 把 other（更高优先级层）的权限叠加到 p 上（标量非空覆盖，
// 列表按 OverlayList 的优先级规则合并：高优先级授权/否决覆盖低优先级的
// 相反表态，其余累加去重——否决标记由 ApplyDenies 统一结算）。
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

// isDeny 判断列表项是否为否决标记（"!X"）。
func isDeny(v string) bool {
	return strings.HasPrefix(v, denyPrefix) && len(v) > len(denyPrefix)
}

// ApplyDenies 处理列表字段的否决项：从最终合并结果中移除被否决的值（或
// 精确 token），并删除否决标记本身。对齐 flatpak override 的
// --nosocket/--nofilesystem 等收窄语义。不关心未命中警告时使用本方法。
func (p *Permissions) ApplyDenies() {
	p.ApplyDeniesWarned()
}

// ApplyDeniesWarned 同 ApplyDenies，但返回"否决未命中"警告：某否决值
// 未移除任何已授权项时（拼写/格式与原授权 token 不一致），静默 no-op
// 是最危险的陷阱，此处显式产出警告，由调用方打印到 stderr。env 字段
// 不参与否决（按变量名移除统一走 unset_env，见 ValidateDenyValues）。
func (p *Permissions) ApplyDeniesWarned() []string {
	var warns []string
	var ws []string
	p.Share, ws = applyDenyWarned(p.Share, "--noshare")
	warns = append(warns, ws...)
	p.Socket, ws = applyDenyWarned(p.Socket, "--nosocket")
	warns = append(warns, ws...)
	p.Device, ws = applyDenyWarned(p.Device, "--nodevice")
	warns = append(warns, ws...)
	p.Allow, ws = applyDenyWarned(p.Allow, "--noallow")
	warns = append(warns, ws...)
	p.FS, ws = applyDenyWarned(p.FS, "--nofilesystem")
	warns = append(warns, ws...)
	p.DBus, ws = applyDenyWarned(p.DBus, "--nodbus")
	warns = append(warns, ws...)
	p.AllowSyscalls, ws = applyDenyWarned(p.AllowSyscalls, "allow_syscalls")
	warns = append(warns, ws...)
	p.Harden, ws = applyDenyWarned(p.Harden, "harden")
	warns = append(warns, ws...)
	p.NetBackendArgs, ws = applyDenyWarned(p.NetBackendArgs, "net_backend_args")
	warns = append(warns, ws...)
	p.UnsetEnv, ws = applyDenyWarned(p.UnsetEnv, "unset_env")
	warns = append(warns, ws...)
	p.RawBwrap, ws = applyDenyWarned(p.RawBwrap, "raw_bwrap")
	warns = append(warns, ws...)
	p.RawDBus, ws = applyDenyWarned(p.RawDBus, "raw_dbus")
	warns = append(warns, ws...)
	return warns
}

// applyDenyWarned 返回移除否决项后的列表与未命中警告。
// 规则：收集所有 "!X"，然后从列表中同时移除 "!X" 标记与精确匹配的 X；
// 某 X 一个已授权项都没移除时产出一条警告（拼写/格式不一致会静默失效）。
func applyDenyWarned(list []string, what string) ([]string, []string) {
	if len(list) == 0 {
		return list, nil
	}
	denied := make(map[string]struct{})
	kept := make([]string, 0, len(list))
	for _, v := range list {
		if isDeny(v) {
			denied[v[len(denyPrefix):]] = struct{}{}
			continue
		}
		kept = append(kept, v)
	}
	if len(denied) == 0 {
		return kept, nil
	}
	out := make([]string, 0, len(kept))
	for _, v := range kept {
		if _, bad := denied[v]; bad {
			continue
		}
		out = append(out, v)
	}
	// 未命中 = 否决的 X 在已授权项 kept 中根本不存在（拼写/格式不一致）
	var warns []string
	for x := range denied {
		if !inList(kept, x) {
			warns = append(warns, fmt.Sprintf(
				"警告: %s 否决 %q 未命中任何已授权项（否决需逐字重复原授权 token，请检查拼写与格式）",
				what, x))
		}
	}
	sort.Strings(warns)
	return Dedupe(out), warns
}

// ValidateDenyValues 校验所有否决标记（"!X"）中的 X 本身是合法值。
// 否决 FLAG（--nodevice 等）缺值时会吞掉后续 FLAG（Go flag 对非布尔
// FLAG 无条件取下一个参数），若不校验否决值，吞进来的 "--dry-run" 等
// 会被当成一次静默否决而不报错。校验后否决 FLAG 与授权 FLAG 一样在
// 拿到非法值时报错。同样覆盖配置文件中的 "!" 前缀写法。
func (p *Permissions) ValidateDenyValues() error {
	for _, group := range []struct {
		name   string
		values []string
		list   []string
	}{
		{"--noshare", ShareValues, p.Share},
		{"--nosocket", SocketValues, p.Socket},
		{"--nodevice", DeviceValues, p.Device},
		{"--noallow", AllowValues, p.Allow},
		{"harden", HardenValues, p.Harden},
	} {
		for _, v := range group.list {
			if !isDeny(v) {
				continue
			}
			inner := v[len(denyPrefix):]
			if !inList(group.values, inner) {
				return fmt.Errorf("无效的 %s 否决值 %q（可选：%s）",
					group.name, inner, strings.Join(group.values, ","))
			}
		}
	}
	for _, v := range p.FS {
		if !isDeny(v) {
			continue
		}
		if _, _, err := ParseFS(v[len(denyPrefix):]); err != nil {
			return fmt.Errorf("无效的 --nofilesystem 否决值: %v", err)
		}
	}
	for _, v := range p.DBus {
		if !isDeny(v) {
			continue
		}
		if err := validateDbusToken(v[len(denyPrefix):]); err != nil {
			return fmt.Errorf("无效的 --nodbus 否决值: %v", err)
		}
	}
	// env 否决已移除：按变量名移除统一走 unset_env（--unset-env FLAG /
	// unset_env 配置项），按"值"匹配环境变量过于脆弱（值随版本变化即静默
	// 失效），且 unset_env 在 bwrap 的 --unset-env 后置语义下严格更强。
	for _, v := range p.Env {
		if isDeny(v) {
			return fmt.Errorf("无效的 env 否决值 %q（env 否决已移除，请使用 unset_env 按变量名移除）", v)
		}
	}
	return nil
}

// validateDbusToken 校验单个 D-Bus 规则 token（target=NAME 或
// preset:NAME[=GLOB]）。供 DbusRules 与否决值校验共用。
func validateDbusToken(tok string) error {
	if strings.HasPrefix(tok, "preset:") {
		name, arg, found := strings.Cut(strings.TrimPrefix(tok, "preset:"), "=")
		if !inList(DBusPresetNames, name) {
			return fmt.Errorf("未知 --dbus 预设 %q（可选：%s）", name, strings.Join(DBusPresetNames, ","))
		}
		if name == "mpris" && (!found || arg == "") {
			return fmt.Errorf("preset:mpris 需要播放器名 glob（如 preset:mpris=firefox.*）")
		}
		return nil
	}
	idx := strings.Index(tok, "=")
	if idx < 0 {
		return fmt.Errorf("无效的 --dbus 项 %q，期望格式 target=NAME（target ∈ %s）",
			tok, strings.Join(DBusTargets, "|"))
	}
	target, name := tok[:idx], tok[idx+1:]
	if !inList(DBusTargets, target) {
		return fmt.Errorf("无效的 --dbus target %q（可选：%s）", target, strings.Join(DBusTargets, "|"))
	}
	if name == "" {
		return fmt.Errorf("--dbus %s 的总线名不能为空", target)
	}
	return nil
}

// ---------- 合并 ----------

// OverlayList 合并低优先级 base 与高优先级 overlay 两个列表：其余值累加
// 并去除完全重复项（保持首次出现的顺序）。同值表态按层覆盖：
//   - overlay 的授权值 "X" 覆盖 base 中的否决标记 "!X"（高优先级授权撤销
//     低优先级否决，如全局 device=["!dri"] 被应用配置 device=["dri"] 覆盖）；
//   - overlay 的否决标记 "!X" 直接叠加，base 中的授权值 "X" 由
//     ApplyDeniesWarned 统一移除（高优先级否决收窄低优先级授权，对齐
//     flatpak override）——这样否决"命中"发生在结算层，未命中警告才准确。
func OverlayList(base, overlay []string) []string {
	if len(overlay) == 0 {
		return Dedupe(base)
	}
	merged := make([]string, 0, len(base)+len(overlay))
	merged = append(merged, base...)
	for _, v := range overlay {
		if !isDeny(v) {
			// 高优先级授权撤销低优先级层的否决标记
			merged = removeAll(merged, denyPrefix+v)
		}
		if !inList(merged, v) {
			merged = append(merged, v)
		}
	}
	return merged
}

// removeAll 原地移除列表中所有等于 v 的项（调用方持有独立副本，可安全复用底层数组）。
func removeAll(list []string, v string) []string {
	out := list[:0]
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
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
		// "-" 开头的 token 是原样透传的 xdg-dbus-proxy 参数（--dbus-arg /
		// raw_dbus），不经 target 校验——由 xdg-dbus-proxy 自行拒绝非法值。
		if strings.HasPrefix(tok, "-") {
			continue
		}
		if err := validateDbusToken(tok); err != nil {
			return nil, err
		}
		idx := strings.Index(tok, "=")
		target, name := tok[:idx], tok[idx+1:]
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
			// 对齐 flatpak（flatpak-run-dbus.c）：portal 是设计上的能力入口，
			// 默认放行全部 portal 接口的调用与 /org/freedesktop/portal/* 下的
			// 广播；各接口在服务端按 caller app-id 二次授权（Document portal
			// 授权表、ScreenCast 恢复 token 等）。caller 身份由 /proc/<代理pid>/
			// root/.flatpak-info + $XDG_RUNTIME_DIR/.flatpak/<instance-id>/
			// bwrapinfo.json 验证（见 daemon 与 dbusproxy 的对应实现）。
			out = append(out,
				"session.talk=org.freedesktop.portal.*",
				"session.call=org.freedesktop.portal.*=*",
				"session.broadcast=org.freedesktop.portal.*=@/org/freedesktop/portal/*",
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
	// 否决项的值本身必须合法（防止 --no-* 吞掉后续 FLAG 后静默通过）
	if err := p.ValidateDenyValues(); err != nil {
		return err
	}

	// 否决项在校验值域前结算（含配置文件内的 "!" 前缀写法）
	p.ApplyDenies()

	// 应用名作为配置文件名与 D-Bus app-id 段的来源，禁止路径分隔符等
	// 非法字符（防止 --app ../../x 越出配置目录；也保证文档语义清晰）。
	if p.App != "" {
		for i, c := range p.App {
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
				c >= '0' && c <= '9' && i > 0 || c == '-' || c == '_' || c == '.' && i > 0
			if !ok {
				return fmt.Errorf("无效的应用名 %q（仅允许字母开头，可含字母/数字/下划线/连字符）", p.App)
			}
		}
	}
	// --home / home 配置为宿主侧 rw 挂载锚点，禁止指向系统根与关键
	// 系统目录（否则等价于 rw 授权整个系统，与逐项 --fs 语义冲突）。
	if p.Home != "" {
		h := filepath.Clean(p.Home)
		if !filepath.IsAbs(h) {
			return fmt.Errorf("无效的 --home %q（必须是绝对路径）", p.Home)
		}
		for _, d := range []string{"/", "/bin", "/boot", "/dev", "/etc",
			"/lib", "/lib64", "/proc", "/root", "/run", "/sbin",
			"/sys", "/usr", "/var"} {
			if h == d {
				return fmt.Errorf("--home 不允许指向系统目录 %s（请指向专用目录）", d)
			}
		}
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
