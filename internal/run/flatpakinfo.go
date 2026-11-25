package run

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"cwrap/internal/perm"
)

// newInstanceID 生成 32 位 hex 随机实例 ID（对齐 flatpak Instance.instance-id）。
// 每次运行唯一：既是 socket 目录名，也是 portal 场景 .flatpak-info 的
// instance-id 与 $XDG_RUNTIME_DIR/.flatpak/<id>/ 目录名。
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
// 该名字同时作为持久化运行目录名（每个配置一个目录，见 instance.go）。
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
