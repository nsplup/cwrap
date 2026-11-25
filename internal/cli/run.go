package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cwrap/internal/bwrap"
	"cwrap/internal/config"
	"cwrap/internal/perm"
	"cwrap/internal/run"
)

// flagPerm 解析 run/permission 共用的权限 FLAG。
// 返回（-- 之后的剩余命令行、-- 前收集的位置参数（permission 的 APP）、
// 是否 --no-global）。
//
// flag 包遇第一个位置参数即停止解析，因此：先按 "--" 预分割（run 的
// 命令部分原样保留，绝不二次解析），再对 FLAG 部分循环解析——每轮
// Parse 停止后把首个位置参数挪出继续，直到耗尽。这使
// "permission export APP --fs rw:/x"（APP 后置 FLAG）与
// "permission export --fs rw:/x APP"（FLAG 后置 APP）两种写法都正确。
func flagPerm(args []string) (*perm.Permissions, []string, []string, bool, bool, bool, error) {
	p := &perm.Permissions{}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var share, socket, device, allow, fsSpecs, dbus, env, syscalls strSlice
	var noShare, noSocket, noDevice, noAllow, noFS, noDBus strSlice
	var harden, unsetEnv, rawBwrap, rawDBus strSlice
	var netArgs strSlice
	fs.StringVar(&p.App, "app", "", "应用名（可省略，省略时 HOME 默认 $HOME/.var/sandbox/home）")
	fs.StringVar(&p.Home, "home", "", "自定义沙箱 HOME 目录")
	fs.Var(&share, "share", "共享: network,ipc")
	fs.Var(&socket, "socket", "socket: x11,wayland,pulseaudio,pipewire,cups,pcsc,ssh-agent,session-bus,system-bus,gpg-agent")
	fs.Var(&device, "device", "设备: dri,kvm,all,input,v4l,ntsync")
	fs.Var(&allow, "allow", "特性: devel,multiarch,portal")
	fs.Var(&fsSpecs, "fs", "文件系统: rw:/path 或 ro:/path（支持 flatpak 关键字，详见 docs/permissions.md）")
	fs.StringVar(&p.Tmp, "tmp", "", "/tmp 处理: tmpfs(默认)|host")
	fs.Var(&dbus, "dbus", "D-Bus: session.talk=NAME / session.see / session.call=NAME=iface.*@path / preset:notify,systray,gamemode,mpris=GLOB,portal,gnome-toolkit,ibus,fcitx")
	fs.StringVar(&p.Seccomp, "seccomp", "", "过滤等级: low|medium|high")
	fs.Var(&syscalls, "allow-syscall", "追加白名单 syscall")
	fs.Var(&env, "env", "环境变量 KEY=VALUE")
	// 否决（对齐 flatpak override --nosocket 等命名：no+字段，无中间横线）
	fs.Var(&noShare, "noshare", "否决已授予的 share 值")
	fs.Var(&noSocket, "nosocket", "否决已授予的 socket 值")
	fs.Var(&noDevice, "nodevice", "否决已授予的 device 值")
	fs.Var(&noAllow, "noallow", "否决已授予的 allow 值")
	fs.Var(&noFS, "nofilesystem", "否决已授予的 fs 项（须逐字重复原授权 token，如 ro:/path）")
	fs.Var(&noDBus, "nodbus", "否决已授予的 dbus 规则/预设（须逐字重复原授权 token）")
	// bubblejail 对齐扩展
	fs.Var(&harden, "harden", "加固: namespaces（递归封死沙箱内建 namespace）,sync（屏蔽落盘 syscall）")
	fs.StringVar(&p.NetBackend, "net-backend", "", "网络后端: host(默认)|pasta|slirp4netns")
	fs.Var(&netArgs, "net-arg", "网络后端附加参数")
	fs.Var(&unsetEnv, "unset-env", "移除环境变量")
	fs.Var(&rawBwrap, "bwrap-arg", "原样透传 bwrap 参数（调试）")
	fs.Var(&rawDBus, "dbus-arg", "原样透传 xdg-dbus-proxy 参数（调试）")
	noGlobal := fs.Bool("no-global", false, "跳过全局配置合并（global.toml）")
	persist := fs.Bool("persist", false, "保存授权为应用配置")
	dry := fs.Bool("dry-run", false, "只打印 bwrap 命令行")
	splitIdx := -1
	for i, a := range args {
		if a == "--" {
			splitIdx = i
			break
		}
	}
	var flagArgs, rest []string
	if splitIdx >= 0 {
		flagArgs, rest = args[:splitIdx], args[splitIdx+1:]
	} else {
		flagArgs = args
	}
	// 循环解析：挪出位置参数（permission 的 APP）后继续，直到耗尽。
	var positional []string
	for {
		if err := fs.Parse(flagArgs); err != nil {
			return nil, nil, nil, false, false, false, err
		}
		rem := fs.Args()
		if len(rem) == 0 {
			break
		}
		positional = append(positional, rem[0])
		flagArgs = rem[1:]
	}
	// 授权 FLAG 不接受否决值："!" 前缀是否决语义，若授权 FLAG 也接受，
	// "--device !dri" 会静默变成否决，与授权直觉相悖。否决必须走对应
	// 的否决通道（--nosocket 等 flatpak 风格否决 FLAG、--unset-env 或
	// 配置文件 "!" 前缀）。
	for _, g := range []struct {
		name string
		list strSlice
		hint string // 提示正确的否决通道
	}{
		{"--share", share, "请改用对应的 --noshare FLAG 或配置文件写法"},
		{"--socket", socket, "请改用对应的 --nosocket FLAG 或配置文件写法"},
		{"--device", device, "请改用对应的 --nodevice FLAG 或配置文件写法"},
		{"--allow", allow, "请改用对应的 --noallow FLAG 或配置文件写法"},
		{"--fs", fsSpecs, "请改用对应的 --nofilesystem FLAG 或配置文件写法"},
		{"--dbus", dbus, "请改用对应的 --nodbus FLAG 或配置文件写法"},
		{"--env", env, "请改用 --unset-env FLAG 或配置文件写法"},
		{"--allow-syscall", syscalls, "请使用配置文件的 \"!\" 前缀写法"},
		{"--harden", harden, "请使用配置文件的 \"!\" 前缀写法"},
		{"--net-arg", netArgs, "请使用配置文件的 \"!\" 前缀写法"},
		{"--unset-env", unsetEnv, "请使用配置文件的 \"!\" 前缀写法"},
		{"--bwrap-arg", rawBwrap, "请使用配置文件的 \"!\" 前缀写法"},
		{"--dbus-arg", rawDBus, "请使用配置文件的 \"!\" 前缀写法"},
	} {
		for _, v := range g.list {
			if strings.HasPrefix(v, "!") {
				return nil, nil, nil, false, false, false, fmt.Errorf(
					"无效的 %s 值 %q：授权 FLAG 不能携带否决前缀 \"!\"，%s", g.name, v, g.hint)
			}
		}
	}
	deny := func(list strSlice) strSlice {
		out := strSlice{}
		for _, v := range list {
			out = append(out, "!"+v)
		}
		return out
	}
	p.Share = append(share, deny(noShare)...)
	p.Socket = append(socket, deny(noSocket)...)
	p.Device = append(device, deny(noDevice)...)
	p.Allow = append(allow, deny(noAllow)...)
	p.FS = append(fsSpecs, deny(noFS)...)
	p.DBus = append(dbus, deny(noDBus)...)
	// env 的否决由 --unset-env（按变量名移除）承担，--no-env 已移除；
	// 配置文件的 "!KEY=VALUE" 写法仍受支持并由 ValidateDenyValues 校验。
	p.Env = env
	p.AllowSyscalls = syscalls
	p.Harden = harden
	p.NetBackendArgs = netArgs
	p.UnsetEnv = unsetEnv
	p.RawBwrap = rawBwrap
	p.RawDBus = rawDBus
	return p, rest, positional, *noGlobal, *persist, *dry, nil
}

// mergeFlags 把 FLAG 值合并到配置合并结果上：
// 标量字段非空覆盖；列表字段按优先级规则合并（高优先级授权/否决覆盖
// 低优先级的相反表态，其余累加去重）。合并后先校验否决值合法性再结算
// 否决项——否则 --nosocket 等否决 FLAG 吞掉后续 FLAG 得到的非法值会被
// 静默当成否决。返回结算时产生的"否决未命中"警告（拼写/格式不一致的
// 否决会静默失效，由调用方打印到 stderr 提醒用户）。
func mergeFlags(base *perm.Permissions, f *perm.Permissions) (*perm.Permissions, []string, error) {
	m := *base
	if f.App != "" {
		m.App = f.App
	}
	if f.Home != "" {
		m.Home = f.Home
	}
	if f.Seccomp != "" {
		m.Seccomp = f.Seccomp
	}
	if f.Tmp != "" {
		m.Tmp = f.Tmp
	}
	m.Share = perm.OverlayList(m.Share, f.Share)
	m.Socket = perm.OverlayList(m.Socket, f.Socket)
	m.Device = perm.OverlayList(m.Device, f.Device)
	m.Allow = perm.OverlayList(m.Allow, f.Allow)
	m.FS = perm.OverlayList(m.FS, f.FS)
	m.DBus = perm.OverlayList(m.DBus, f.DBus)
	m.Env = perm.OverlayList(m.Env, f.Env)
	m.AllowSyscalls = perm.OverlayList(m.AllowSyscalls, f.AllowSyscalls)
	m.Harden = perm.OverlayList(m.Harden, f.Harden)
	m.NetBackendArgs = perm.OverlayList(m.NetBackendArgs, f.NetBackendArgs)
	m.UnsetEnv = perm.OverlayList(m.UnsetEnv, f.UnsetEnv)
	m.RawBwrap = perm.OverlayList(m.RawBwrap, f.RawBwrap)
	m.RawDBus = perm.OverlayList(m.RawDBus, f.RawDBus)
	if f.NetBackend != "" {
		m.NetBackend = f.NetBackend
	}
	if err := m.ValidateDenyValues(); err != nil {
		return nil, nil, err
	}
	warns := m.ApplyDeniesWarned()
	return &m, warns, nil
}

func cmdRun(argv []string) int {
	flags, rest, _, noGlobal, persist, dry, err := flagPerm(argv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "权限错误:", err)
		return 2
	}
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "错误: 需要 -- 待执行命令，例如: cwrap run --app demo -- /bin/echo hi")
		return 2
	}

	// 配置合并：全局 < 应用 < FLAG（--no-global 跳过全局配置）
	merged := &perm.Permissions{}
	if !noGlobal {
		global, _ := config.LoadGlobal()
		merged = global
	}
	if flags.App != "" {
		appCfg, _ := config.LoadApp(flags.App)
		merged.Overlay(appCfg)
	}
	var warns []string
	merged, warns, err = mergeFlags(merged, flags)
	if err != nil {
		fmt.Fprintln(os.Stderr, "权限错误:", err)
		return 2
	}
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, w)
	}
	// --allow portal：预检宿主 flatpak-xdg-utils 的 xdg-open（路径随发行版
	// 而异，config.toml 的 xdg_open_path 可自定义）。未找到时立即警告，
	// 否则 portal 场景下容器内没有 xdg-open 覆盖、链接打开可能失效。
	// 会话执行侧（internal/run）也会解析并打印警告（双保险）。
	if perm.Has(merged.Allow, "portal") {
		if prog, perr := config.LoadProgram(); perr == nil {
			if _, w := bwrap.ResolveXDGOpen(prog.XDGOpenPath); w != "" {
				fmt.Fprintln(os.Stderr, w)
			}
		}
	}
	merged.Seccomp = perm.DefaultSeccomp(merged.Seccomp)
	if merged.Tmp == "" {
		merged.Tmp = perm.DefaultTmp()
	}

	// --fs 与 --tmp 提供的 /tmp 冲突去重：过滤并警告，引导使用 --tmp
	filteredFS, tmpWarnings := perm.FilterTmpFSConflicts(merged)
	if len(tmpWarnings) > 0 {
		for _, w := range tmpWarnings {
			fmt.Fprintln(os.Stderr, w)
		}
		merged.FS = filteredFS
	}

	// 解析双横线后的可执行文件（宿主 PATH），并做权限校验
	cmdPath, err := resolveCmd(rest[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 2
	}
	if err := merged.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "权限错误:", err)
		return 2
	}

	if persist {
		if merged.App == "" {
			fmt.Fprintln(os.Stderr, "错误: --persist 需要应用名（--app 或配置文件）")
			return 2
		}
		if err := config.SaveApp(merged); err != nil {
			fmt.Fprintln(os.Stderr, "保存配置失败:", err)
			return 1
		}
		fmt.Printf("授权已保存到 %s\n", config.AppPath(merged.App))
	}

	if dry {
		spec := *merged
		b, _ := json.MarshalIndent(map[string]any{"argv": append([]string{cmdPath}, rest[1:]...), "spec": spec}, "", "  ")
		fmt.Println(string(b))
		return 0
	}

	return run.Session(merged, append([]string{cmdPath}, rest[1:]...))
}

// resolveCmd 解析可执行文件绝对路径。
func resolveCmd(name string) (string, error) {
	if strings.ContainsRune(name, '/') {
		abs, err := filepath.Abs(name)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(abs); err != nil {
			return "", fmt.Errorf("可执行文件不存在: %s", name)
		}
		return abs, nil
	}
	// 宿主 PATH 查找（注意必须在沙箱外完成）
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		cand := filepath.Join(dir, name)
		if st, err := os.Stat(cand); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return cand, nil
		}
	}
	return "", fmt.Errorf("在宿主 PATH 中找不到命令: %s", name)
}

// ---- permission 子命令 ----

func cmdPermission(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "用法: cwrap permission show|export [APP] [FLAGS...]")
		return 2
	}
	sub, rest := argv[0], argv[1:]
	switch sub {
	case "show":
		flags, _, restPos, noGlobal, _, _, err := flagPerm(rest)
		if err != nil {
			return 2
		}
		merged := &perm.Permissions{}
		if !noGlobal {
			merged, _ = config.LoadGlobal()
		}
		name := flags.App
		if name == "" && len(restPos) > 0 && !strings.HasPrefix(restPos[0], "-") {
			name = restPos[0]
		}
		if name == "" {
			// show 不带 app 时展示（全局+）FLAG
			var warns []string
			merged, warns, err = mergeFlags(merged, flags)
			if err != nil {
				fmt.Fprintln(os.Stderr, "权限错误:", err)
				return 2
			}
			for _, w := range warns {
				fmt.Fprintln(os.Stderr, w)
			}
			merged.Seccomp = perm.DefaultSeccomp(merged.Seccomp)
			if merged.Tmp == "" {
				merged.Tmp = perm.DefaultTmp()
			}
			merged.App = "(未指定)"
		} else {
			appCfg, _ := config.LoadApp(name)
			merged.Overlay(appCfg)
			var warns []string
			merged, warns, err = mergeFlags(merged, flags)
			if err != nil {
				fmt.Fprintln(os.Stderr, "权限错误:", err)
				return 2
			}
			for _, w := range warns {
				fmt.Fprintln(os.Stderr, w)
			}
			merged.Seccomp = perm.DefaultSeccomp(merged.Seccomp)
			if merged.Tmp == "" {
				merged.Tmp = perm.DefaultTmp()
			}
		}
		fmt.Print(merged.Describe())
		return 0
	case "export":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "用法: cwrap permission export APP [FLAGS...]")
			return 2
		}
		flags, _, positional, noGlobal, _, _, err := flagPerm(rest)
		if err != nil {
			return 2
		}
		name := flags.App
		if name == "" && len(positional) > 0 {
			name = positional[0]
		}
		if name == "" {
			fmt.Fprintln(os.Stderr, "错误: 需要 APP 名或 --app FLAG")
			return 2
		}
		flags.App = name
		merged := &perm.Permissions{}
		if !noGlobal {
			merged, _ = config.LoadGlobal()
		}
		var warns []string
		merged, warns, err = mergeFlags(merged, flags)
		if err != nil {
			fmt.Fprintln(os.Stderr, "权限错误:", err)
			return 2
		}
		for _, w := range warns {
			fmt.Fprintln(os.Stderr, w)
		}
		merged.Seccomp = perm.DefaultSeccomp(merged.Seccomp)
		if merged.Tmp == "" {
			merged.Tmp = perm.DefaultTmp()
		}
		if err := merged.Validate(); err != nil {
			fmt.Fprintln(os.Stderr, "权限错误:", err)
			return 2
		}
		if err := config.SaveApp(merged); err != nil {
			fmt.Fprintln(os.Stderr, "保存失败:", err)
			return 1
		}
		fmt.Printf("已写入 %s\n", config.AppPath(name))
		return 0
	default:
		fmt.Fprintf(os.Stderr, "未知子命令 permission %s\n", sub)
		return 2
	}
}

// ---- ps / kill / clean ----
//
// 无守护进程：三个命令都直接读写持久化实例注册表
// （$XDG_RUNTIME_DIR/cwrap/<应用名>/instances.json，见 internal/run）。

func cmdPS() int {
	runs := run.List()
	if len(runs) == 0 {
		fmt.Println("当前没有运行中的沙箱")
		return 0
	}
	fmt.Printf("%-34s %-8s %s\n", "ID", "PID", "APP")
	for _, r := range runs {
		fmt.Printf("%-34s %-8d %s\n", r.ID, r.PID, r.App)
	}
	return 0
}

func cmdKill(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "用法: cwrap kill <ID|APP>")
		return 2
	}
	if err := run.Kill(args[0]); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		return 1
	}
	fmt.Println("已发送终止信号")
	return 0
}

func cmdClean() int {
	n := run.Clean()
	fmt.Printf("清理了 %d 个陈旧目录\n", n)
	return 0
}
