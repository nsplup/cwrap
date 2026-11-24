// Package cli 实现 cwrap 命令行入口与子命令分发。
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"cwrap/internal/daemon"
	"cwrap/internal/version"
)

// strSlice 支持重复 FLAG 与逗号分隔两种写法。
type strSlice []string

func (s *strSlice) String() string { return strings.Join(*s, ",") }
func (s *strSlice) Set(v string) error {
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			*s = append(*s, item)
		}
	}
	return nil
}

// Main 是 CLI 主入口，返回进程退出码。
func Main(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "run":
		return cmdRun(args[1:])
	case "permission":
		return cmdPermission(args[1:])
	case "ps":
		return cmdPS()
	case "kill":
		return cmdKill(args[1:])
	case "clean":
		return cmdClean()
	case "daemon":
		if err := daemon.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "cwrapd:", err)
			return 1
		}
		return 0
	case "version", "--version", "-v":
		fmt.Println("cwrap " + version.Value)
		return 0
	case "help", "--help", "-h":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "未知命令 %q\n\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	usageTo(os.Stdout)
}

// usageTo 输出帮助文本（独立出 io.Writer 便于测试断言内容）。
// 列表 FLAG（--share/--socket/--fs 等）均支持重复传入与逗号分隔两种写法。
func usageTo(w io.Writer) {
	fmt.Fprint(w, `cwrap - 通俗易懂的 Flatpak 式权限沙箱（bubblewrap 上层包装）

用法:
  cwrap run [FLAGS] -- 命令 [参数...]        在沙箱中运行程序（默认零权限）
  cwrap permission show [APP] [FLAGS]        显示合并后的有效权限（共用下列 FLAG）
  cwrap permission export APP [FLAGS]        将授权固化为应用配置文件
  cwrap ps                                   列出运行中的沙箱
  cwrap kill <ID|APP>                        终止运行中的沙箱
  cwrap clean                                清扫陈旧的临时目录
  cwrap daemon                               启动守护进程（通常自动拉起）
  cwrap version | help

授权 FLAG（默认零权限，需要什么给什么）:
  --app NAME                    应用名（决定 HOME 与配置文件；省略时 HOME 为
                                $HOME/.var/sandbox/home）
  --home PATH                   自定义沙箱 HOME（默认 $HOME/.var/sandbox/NAME）
  --share LIST                  network, ipc
  --socket LIST                 x11, wayland, pulseaudio, pipewire, cups, pcsc,
                                ssh-agent, gpg-agent,
                                session-bus / system-bus（未过滤直通，谨慎使用）
  --device LIST                 dri, kvm, all, input, v4l, ntsync
  --allow LIST                  devel, multiarch, portal（portal 权限包）
  --fs SPEC                     挂载宿主目录: rw:PATH / ro:PATH
                                PATH 支持绝对路径与关键字 home/host/host-os/
                                host-etc/xdg-*/~/path；尾缀 ? 容错不存在的目标
  --dbus SPEC                   session|system × talk/own/see/call/broadcast，
                                或预设 preset:notify / systray / gamemode /
                                mpris=GLOB / portal / gnome-toolkit / ibus / fcitx
  --env KEY=VALUE               注入环境变量
  --tmp MODE                    /tmp 处理: tmpfs（默认，全空）/ host（宿主 /tmp）
  --seccomp LEVEL               low（宽松黑名单）/ medium（flatpak 级，默认）/
                                high（默认拒绝+白名单，含 W^X 保护，最严格）
  --allow-syscall LIST          追加白名单 syscall（与等级叠加）
  --harden LIST                 namespaces（递归封死沙箱内建 ns）/
                                sync（落盘 syscall 返回 0）
  --net-backend MODE            host（默认）/ pasta / slirp4netns（独立网络栈）
  --net-arg LIST                网络后端附加参数
  --bwrap-arg / --dbus-arg      原样透传 bwrap / xdg-dbus-proxy 参数（调试）

否决 FLAG（对齐 flatpak override --nosocket；否决值同样校验合法性）:
  --no-share/--no-socket/--no-device/--no-allow/--no-fs/--no-dbus VALUE
                                否决已授予的对应权限
  --unset-env NAME              按变量名移除环境变量（移除 env 的唯一 FLAG 通道）

配置与其他:
  --no-global                   跳过全局配置合并（~/.config/cwrap/global.toml）
  --persist                     将本次合并后的授权保存为应用配置
  --dry-run                     只打印合并后的 spec，不实际运行

优先级与否决:
  全局配置 < 应用配置 < 命令行 FLAG；高优先级的授权可覆盖低优先级的否决
  （全局 device=["!dri"] + 应用 device=["dri"] -> 最终授予 dri），高优先级
  的否决同样可收窄低优先级的授权；同一层内否决优先于授权。否决只能通过
  --no-* FLAG、--unset-env 或配置文件的 "!" 前缀表达；授权 FLAG 不接受
  "!" 前缀值。

示例:
  cwrap run --app demo --share network --socket x11 -- curl https://example.com
  cwrap run --app demo --seccomp high --allow-syscall memfd_create -- ./build.sh
  cwrap run --app demo --device input --dbus preset:notify -- /usr/bin/game
  cwrap run --app demo --env LANG=C.utf8 --unset-env SECRET_TOKEN -- ./app
  cwrap permission export demo --device dri --fs ro:/opt/data    # 固化授权
  cwrap run --app demo --dry-run -- /app/check                    # 预检权限
`)
}
