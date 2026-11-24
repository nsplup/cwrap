# cwrap 权限模型手册（Flatpak / bubblejail 对齐版）

cwrap 的权限语义对齐 Flatpak 与 bubblejail，表达更直白：**默认零权限**，
任何能力都必须通过 FLAG 或 TOML 配置显式授予。

配置加载顺序：

```
~/.config/cwrap/global.toml（全局默认）
  < ~/.config/cwrap/apps/<APP>.toml（应用配置）
    < 命令行 FLAG（逐项合并）
```

合并规则：标量字段（app/home/seccomp/tmp/net_backend）非空覆盖；
列表字段（share/socket/device/allow/fs/dbus/env/allow_syscalls/harden/
net_backend_args/unset_env/raw_bwrap/raw_dbus）累加并去重。

**否决语义**（对齐 `flatpak override` 的 `--nosocket`/`--nofilesystem` 等
命名）：任何列表项支持 `!` 前缀（TOML 写 `"!x11"`），或使用
`--noshare/--nosocket/--nodevice/--noallow/--nofilesystem/--nodbus` FLAG
（fs/dbus 否决须逐字重复原授权 token，与 flatpak 相同）；环境变量按变量
名移除统一走 `--unset-env` / `unset_env`（`--no-env` 已移除，与
`--unset-env` 重复；env 的 `"!KEY=VALUE"` 写法同样已废弃）。否决作用于
合并结果：被否决的值从授权列表中整体移除。否决项的值同样会校验合法性
——否决 FLAG 吞到非法值（如误吞后续 FLAG）时会直接报错而非静默否决；
否决未命中任何已授权项时会在 stderr 打印警告。旧式
`--no-share/--no-socket` 等横线写法已移除。

**优先级**：授权与否决按所在层比较，高优先级层（应用配置 > 全局配置、
命令行 FLAG > 配置文件）的表态覆盖低优先级层——高优先级授权可撤销低
优先级否决（全局 `device=["!dri"]` + 应用 `device=["dri"]` → 最终授予
`dri`），高优先级否决也可收窄低优先级授权；同一层内否决优先于授权。
授权 FLAG（`--device` 等）不接受 `!` 前缀值，否决只能走 `--no-*` FLAG
或配置文件的 `"!"` 前缀写法。

## 权限三栏对照矩阵

### 共享（share）

| cwrap | Flatpak | bubblejail | 说明 |
|---|---|---|---|
| `network` | `--share=network` | `network` 服务 | 含 resolv.conf 断链修复（systemd-resolved symlink 场景补挂 `/run/systemd/resolve`） |
| `ipc` | `--share=ipc` | （默认隔离） | 不授予则 `--unshare-ipc` |
| `--net-backend pasta` | 无 | `pasta_network` 服务 | 独立用户态网络栈；bwrap 侧 `--unshare-net` + `--info-fd` 取 PID 后由 cwrapd 挂接 |
| `--net-backend slirp4netns` | 无 | `slirp4netns` 服务 | 同上；DNS 注入 `10.0.2.3`（`--ro-bind-data` 覆盖 resolv.conf） |

### socket

| cwrap | Flatpak | bubblejail | bwrap 生成 |
|---|---|---|---|
| `x11` | `--socket=x11` | `x11` 服务 | `DISPLAY` 透传 + `--ro-bind-try /tmp/.X11-unix`；`XAUTHORITY` 挂到 `/tmp/.Xauthority` 并改写环境变量（写路径隔离）；Wayland 会话下 `XDG_SESSION_TYPE=x11` |
| `wayland` | `--socket=wayland` | `wayland` 服务 | 宿主任意名 socket → 统一挂为 `wayland-0`；`GDK_BACKEND/QT_QPA_PLATFORM/SDL_VIDEODRIVER/XDG_SESSION_TYPE=wayland` |
| `pulseaudio` | `--socket=pulseaudio` | `pulse_audio` 服务 | **仅 bind native socket**：`--bind-try <rt>/pulse/native`（rw）+ `PULSE_SERVER` |
| `pipewire` | `--socket=pipewire` | `pipewire` 服务 | `--ro-bind-try <rt>/pipewire-0` |
| `cups` | `--socket=cups` | 无 | `--ro-bind-try <rt>/cups` |
| `pcsc` | `--socket=pcsc` | 无 | `--ro-bind-try /run/pcscd` |
| `ssh-agent` | `--socket=ssh-agent` | 无 | `--ro-bind-try <rt>/ssh-auth`（`SSH_AUTH_SOCK` 改写） |
| `gpg-agent` | `--socket=gpg-agent` | 无 | `--ro-bind-try ~/.gnupg` + `--bind-try <rt>/gnupg` |
| `session-bus` | `--socket=session-bus` | （默认无） | **未过滤直通**：`--bind-try <rt>/bus`，不启动代理，打印警告 |
| `system-bus` | `--socket=system-bus` | （默认无） | `--ro-bind-try /run/dbus/system_bus_socket`，不启动代理 |

### D-Bus（dbus）

| cwrap | Flatpak | bubblejail | 说明 |
|---|---|---|---|
| `session.talk=NAME` 等 | `--talk-name/--own-name` | 对应服务规则 | 经 xdg-dbus-proxy `--filter`（默认零放行） |
| `session.see=NAME` | （内部） | DbusSessionSee | `--see=NAME` |
| `session.call=NAME=iface.glob@path` | （内部） | DbusSessionCall | `--call=...` |
| `session.broadcast=...` | （内部） | DbusSessionBroadcast | `--broadcast=...` |
| `preset:notify` | portal Notification | `notify` 服务 | talk + call org.freedesktop.Notifications |
| `preset:systray` | 无 | `systray` 服务 | org.kde.StatusNotifierWatcher |
| `preset:gamemode` | 无 | `gamemode` 服务 | com.feralinteractive.GameMode |
| `preset:mpris=GLOB` | `--own-name` | `mpris` 服务 | `--own=org.mpris.MediaPlayer2.<GLOB>` |
| `preset:portal` | （默认可见） | `xdg_desktop_portal` 基座 | talk Desktop + Properties/Request/Session 调用规则 |
| `preset:gnome-toolkit` | 无 | `gnome_toolkit` 服务 | portal.*/dconf/gtk.vfs |
| `preset:ibus` / `preset:fcitx` | 输入法 portal | `ibus`/`fcitx` 服务 | talk 规则 + IM 环境变量（GTK/QT_IM_MODULE 等） |
| `--dbus-arg ARG` | 无 | `debug` 服务 raw_dbus_args | 原样透传 xdg-dbus-proxy |
| `--allow portal` | portal 体验 | `xdg_desktop_portal` 完整包 | memfd 伪 `/.flatpak-info`（`--ro-bind-data`）+ `GTK_USE_PORTAL=1` + 自动注入 `preset:portal` + flatpak-xdg-utils 的 xdg-open 覆盖（存在时） |

### 设备（device）

| cwrap | Flatpak | bubblejail | bwrap 生成 |
|---|---|---|---|
| `dri` | `--device=dri` | `direct_rendering` 服务 | `--dev-bind /dev/dri` + sysfs + **NVIDIA**：`/dev/nvidia*`、`/sys/module/nvidia*`；`/sys/class/drm` 逐条 symlink 重建 |
| `kvm` | `--device=kvm` | 无 | `--dev-bind-try /dev/kvm` |
| `all` | `--device=all` | 无 | `--dev-bind /dev`（整棵 devtmpfs，谨慎） |
| `input` | 无 | `joystick` 服务 | `/dev/input/js*`、`event*` + `/sys/class/input` symlink 重建 |
| `v4l` | `--device=all`（子集） | `v4l` 服务 | `/dev/video*`、`/dev/media*` + video4linux/media sysfs |
| `ntsync` | 无 | `ntsync` 服务 | `--dev-bind-try /dev/ntsync` |

### 文件系统（fs）

`--fs` 完整支持 Flatpak 关键字：`home`/`~`/`~/sub`、`host`、`host-os`、
`host-etc`、`xdg-config[/sub]`、`xdg-data[/sub]`、`xdg-cache[/sub]`、
`xdg-run[/sub]`、`xdg-desktop/documents/download/music/pictures/
public-share/templates/videos`；尾缀 `?` 表示目标不存在不报错
（对应 bubblejail `home_share`/`root_share` 的 `home_paths[_read_only]`）。
`--tmp tmpfs|host` 管辖 /tmp（对齐 bubblejail 的沙箱 tmpfs 语义）。

### 加固与调试（harden / raw）

| cwrap | 基准 | 说明 |
|---|---|---|
| `--harden namespaces` | bubblejail `namespaces_limits` | 沙箱 pid1（sh 包装器）写零 `/proc/sys/user/max_*_namespaces` 后 exec；pid1 保留 userns 内 caps（放弃 `--cap-drop ALL`） |
| `--harden sync` | bubblejail `filter_disk_sync` | `sync/fsync/fdatasync/syncfs/sync_file_range/msync` → 返回 0（假装成功） |
| `--bwrap-arg` | bubblejail `debug.raw_bwrap_args` | 原样追加 bwrap 参数 |
| `--dbus-arg` | bubblejail `debug.raw_dbus_args` | 原样追加 xdg-dbus-proxy 参数 |
| `--unset-env` | Flatpak `--unset-env` | 与 `--clearenv` 叠加时为幂等兼容语义 |

## FS 规则

- `--fs` 的关键字锚点展开（`~`、`home`、`xdg-*`）**禁止上溯出锚点目录**
  （如 `xdg-run/../`、`~/../`）：上溯等价于未经声明的全盘授权，需要时请
  用绝对路径显式授权；绝对路径允许，但归一化后指向 `/` 的写法（如
  `rw:/usr/../`）会被根目录禁令拒绝。

## seccomp

- `low`：仅内核级高危黑名单（bpf/kexec/模块/swap/reboot 等）。
- `medium`：flatpak 默认级黑名单（追加 ptrace 系、keyctl、userns 等）；
  `--allow devel` 时剔除 ptrace/perf_event_open。
- `high`：默认拒绝 + 白名单 + W^X 检查（`--allow devel` 解除）。
- `--allow-syscall NAME` 任意档追加白名单；`--harden sync` 任意档追加
  落盘调用屏蔽（返回 0）。
- BPF 由纯 Go 生成，memfd 传递给 `bwrap --seccomp`，不落盘。

基线 bwrap 参数额外包含 `--cap-drop ALL`（`--harden namespaces` 除外）。

## D-Bus

- 未授予任何 `--dbus`/socket 总线权限时**不启动代理**，沙箱内没有总线；
  此时 `DBUS_SESSION_BUS_ADDRESS` 被显式设为 `disabled`（对齐 flatpak，
  GLib ≥2.80 会静默接受）。
- 授予后由 `xdg-dbus-proxy` 接管，`--filter` 生效且默认零放行规则；
  规则按 `session.`/`system.` 前缀分流到对应代理。
- **`--allow portal` 会自动注入 `preset:portal` 规则**（在总线判定之前），
  因此 portal 包自带可用的会话总线（仅 portal 访问）。
- **portal 身份链**（对齐 flatpak）：`--allow portal` 时伪造规范形态的
  `/.flatpak-info`（`[Application] name = org.cwrap.App.<应用名>`，按应用
  独立），xdg-dbus-proxy 由 bwrap 包装运行使其命名空间根里可见该文件
  （flatpak `add_bwrap_wrapper` 同款），并落盘
  `$XDG_RUNTIME_DIR/.flatpak/<instance-id>/bwrapinfo.json`（含沙箱
  child-pid）——这三者共同通过 xdg-desktop-portal 的 caller 身份验证；
  缺失任一项则 caller 被当作宿主应用（bubblejail 式妥协）。
  Document portal 挂载点（`/run/user/<uid>/doc`，rw）同步自动挂载。
- portal 预设规则为 flatpak 同款宽规则：talk + 任意接口 call +
  `/org/freedesktop/portal/*` 广播；各接口在服务端按 caller app-id
  二次授权。与其他 dbus 规则重叠时为并集语义（xdg-dbus-proxy 不报错）。
- **托盘图标**（libayatana/StatusNotifier）需要显式授予：
  `--dbus preset:systray`；同时需要会话总线（portal 包或任意 dbus 规则
  均可提供）。
- 代理 socket 写入 `$XDG_RUNTIME_DIR/cwrap/<时间戳>/session|system`，
  结束后由 cwrapd 清理；沙箱内地址固定 `/run/cwrap/sessionBus|systemBus`。
- `--socket gpg-agent` 仅**只读**绑定具体 agent socket 文件
  （`S.gpg-agent`、`S.gpg-agent.extra`、`S.gpg-agent.ssh`，对齐 flatpak
  `flatpak-run-sockets.c`）；沙箱无法写宿主 gnupg 目录。
- `--dbus-arg` / `raw_dbus`：原样透传 xdg-dbus-proxy 参数（调试用），
  同时作用于 session 与 system 两个代理；非法值由 xdg-dbus-proxy 报错。
- 已知边界：基线只读挂载 `/etc` 会向沙箱暴露宿主敏感文件
  （如 `/etc/shadow` 哈希），与 flatpak/bubblejail 语义一致。

## 已知限制

- X11 没有逐窗口权限（与 Flatpak 一致）；细粒度隔离请用 Wayland。
- `--socket session-bus/system-bus` 是**未过滤直通逃生门**（与 Flatpak
  同名语义），授予即放弃 D-Bus 治理。
- 可执行文件自动挂载只做一层解析（含 shebang 解释器）。
- pasta/slirp4netns 需要宿主安装对应二进制（运行时检测）。
- `high` 白名单按 amd64 构建；其他架构用 low/medium 或 `--allow-syscall`。
- `--harden namespaces` 以放弃 pid1 的 `--cap-drop ALL` 为代价。
