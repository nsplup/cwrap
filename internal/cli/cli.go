// Package cli 实现 cwrap 命令行入口与子命令分发。
package cli

import (
	"fmt"
	"os"
	"strings"

	"cwrap/internal/daemon"
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
		fmt.Println("cwrap 1.0.0")
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
	fmt.Print(`cwrap - 通俗易懂的 Flatpak 式权限沙箱（bubblewrap 上层包装）

用法:
  cwrap run [FLAGS] -- 命令 [参数...]        在沙箱中运行程序（默认零权限）
  cwrap permission show [APP] [FLAGS]        显示合并后的有效权限
  cwrap permission export APP [FLAGS]        将授权固化为应用配置文件
  cwrap ps                                   列出运行中的沙箱
  cwrap kill <ID|APP>                        终止运行中的沙箱
  cwrap clean                                清扫陈旧的临时目录
  cwrap daemon                               启动守护进程（通常自动拉起）
  cwrap version

run 权限 FLAG（默认全部拒绝，需要什么给什么）:
  --app NAME                    应用名（决定 HOME 与配置文件）
  --home PATH                   自定义沙箱 HOME（默认 $HOME/.var/sandbox/NAME）
  --share LIST                  network, ipc
  --socket LIST                 x11, wayland, pulseaudio, pipewire, cups, pcsc, ssh-agent
  --device LIST                 dri, kvm, all
  --allow LIST                  devel, multiarch
  --fs SPEC                     挂载宿主目录: rw:/path 或 ro:/path（可多次）
  --dbus SPEC                   session.talk=NAME / session.own=NAME /
                                system.talk=NAME / system.own=NAME（可多次）
  --seccomp LEVEL               low（宽松黑名单）/ medium（flatpak 级，默认）/
                                high（默认拒绝+白名单，最严格）
  --allow-syscall LIST          追加白名单 syscall（与等级叠加）
  --env KEY=VALUE               注入环境变量（可多次）
  --persist                     将本次合并后的授权保存为应用配置
  --dry-run                     只打印 bwrap 命令行，不实际运行

示例:
  cwrap run --app demo --share network --socket x11 -- curl https://example.com
  cwrap run --app demo --seccomp high --allow-syscall memfd_create -- ./build.sh
`)
}
