# cwrap

**cwrap** 是面向 [bubblewrap](https://github.com/containers/bubblewrap) 的上层包装器（Go CLI），
权限模型看齐 [Flatpak](https://github.com/flatpak/flatpak)，但语义更直白：

- **默认零权限**——无网络、无 X11/Wayland、无 D-Bus、HOME 完全隔离、seccomp 最严格档可用；
- 所有能力通过 FLAG 或 TOML 配置文件**显式授权**；
- **无守护进程**：`cwrap run` 主进程直接监管沙箱，转发信号/退出码；主沙箱与
  D-Bus 代理沙箱的生命周期经 `bwrap --die-with-parent`（内核 PR_SET_PDEATHSIG）
  与主进程严格同步（主进程退出即沙箱终止，含被 SIGKILL 的情形）；
- seccomp BPF 过滤器由 cwrap **纯 Go 内存生成**，经 memfd 以 FD 传给 `bwrap --seccomp`；
- D-Bus 由 `xdg-dbus-proxy` 接管，**默认零放行规则**；临时文件位于**持久化的
  按配置目录** `$XDG_RUNTIME_DIR/cwrap/<应用名>/<instanceID>/`，目录内
  `instances.json` 记录 instanceID 与 PID 的映射，每次启动先清扫残留实例。

依赖运行时：`bwrap`（必装）、`xdg-dbus-proxy`（仅使用 D-Bus 权限时需要）。
无需 root（bubblewrap 走非特权 user namespace）。

## 依赖与版本要求

- **bubblewrap（bwrap）**：`--allow portal` 的 portal 身份链依赖
  `--json-status-fd`（**bwrap ≥ 0.9.0**，2024-07 发布）；旧版本下 portal
  启动会直接报 `Unknown option`。其余功能对版本无特殊要求。

## 安装

```sh
tar -xzf cwrap-linux-amd64.tar.gz
sudo install -m755 cwrap/cwrap /usr/local/bin/
```

## 快速上手

```sh
# 最小权限：HOME 隔离到 $HOME/.var/sandbox/demo，无任何共享
cwrap run --app demo -- /bin/echo hello

# 授权网络 + X11 + D-Bus 会话总线的两个名字
cwrap run --app demo \
  --share network --socket x11 \
  --dbus session.talk=org.freedesktop.Notifications \
  --dbus session.own=org.example.Demo \
  -- /usr/bin/myapp

# 高严格 seccomp（默认拒绝+白名单，含 W^X 保护）并追加白名单
cwrap run --app build --seccomp high --allow-syscall memfd_create,clone3 -- ./build.sh

# /tmp 两档：全空 tmpfs（默认）/ 宿主 /tmp
cwrap run --app demo --tmp tmpfs -- /usr/bin/myapp
cwrap run --app demo --tmp host -- /usr/bin/myapp
cwrap run --app demo --tmp /mnt/share/tmp -- /usr/bin/myapp

# fs 授权支持 flatpak 关键字展开（home/host/xdg-* 等，? 表示不存在不报错）
cwrap run --app demo --fs ro:xdg-download? --fs rw:~/project -- /usr/bin/myapp

# 把本次授权固化为 demo 的配置文件
cwrap run --app demo --share network --persist -- /usr/bin/myapp

# 对齐扩展（Flatpak / bubblejail 语义，详见 docs/permissions.md）
# 权限否决（对齐 flatpak override）：应用配置给了 x11，CLI 层撤销
cwrap run --app demo --no-socket x11 -- /usr/bin/myapp

# D-Bus 预设（bubblejail notify/systray/gamemode/mpris 服务）
cwrap run --app demo --dbus preset:notify --dbus preset:mpris='firefox.*' -- /usr/bin/myapp

# portal 权限包（伪 .flatpak-info + GTK_USE_PORTAL + xdg-open 覆盖；
# 自动注入 portal 的 D-Bus 规则，settings portal / 文件选择器可用）
cwrap run --app demo --allow portal -- /usr/bin/myapp

# portal + 托盘（libayatana/StatusNotifier 需要显式授予 systray 预设）
cwrap run --app demo --allow portal --dbus preset:systray -- /usr/bin/myapp

# 手柄 / 摄像头 / Wine ntsync（bubblejail joystick/v4l/ntsync 服务）
cwrap run --app demo --device input,v4l,ntsync -- /usr/bin/game

# 独立用户态网络栈（bubblejail pasta_network/slirp4netns 服务）
cwrap run --app demo --net-backend pasta -- /usr/bin/myapp

# 加固：递归封死沙箱内建 namespace + 屏蔽落盘 syscall
cwrap run --app demo --harden namespaces,sync -- /usr/bin/myapp

# 未过滤总线直通逃生门（对齐 flatpak --socket=session-bus，谨慎）
cwrap run --app demo --socket session-bus -- /usr/bin/myapp
```

## 命令

| 命令 | 说明 |
|---|---|
| `cwrap run [FLAGS] -- CMD [ARGS…]` | 在沙箱中运行命令 |
| `cwrap permission show [APP] [FLAGS…]` | 显示合并后的有效权限 |
| `cwrap permission export APP [FLAGS…]` | 把 FLAGS/全局合并结果写入应用配置 |
| `cwrap ps` | 列出运行中的沙箱（读持久化实例注册表） |
| `cwrap kill <ID\|APP>` | 终止沙箱 |
| `cwrap clean` | 清扫陈旧的实例目录 |

`--` 之后的可执行文件若不在沙箱挂载范围内（如 `~/bin/foo`），cwrap 会
自动以只读方式挂入（脚本会连带 shebang 解释器）。

完整 FLAG 说明与 seccomp 等级明细见 [docs/permissions.md](docs/permissions.md)。

## 配置文件

全局 `~/.config/cwrap/global.toml`、应用 `~/.config/cwrap/apps/<app>.toml`：

```toml
app = "demo"
seccomp = "medium"          # low | medium | high
tmp = "tmpfs"               # tmpfs(默认，全空) | host(宿主 /tmp)
share = ["network"]
socket = ["x11", "wayland"]
device = []
allow = []               # devel, multiarch, portal
fs = ["ro:/opt/data", "ro:xdg-download?"]   # 支持 flatpak 关键字，? = 不存在不报错
dbus = [                                  # 支持 preset: 预设
  "session.talk=org.freedesktop.Notifications",
  "session.own=org.example.Demo",
  "preset:notify",
]
harden = []               # namespaces, sync
net_backend = ""          # host | pasta | slirp4netns
allow_syscalls = []
env = ["MYAPP_DEBUG=1"]
unset_env = []
# home = "/srv/sandbox/demo"   # 自定义隔离目录
# 否决示例：socket = ["!x11"]  # 从最终授权中移除 x11
```

优先级：全局 < 应用 < 命令行 FLAG。
标量字段逐级覆盖；列表字段累加并去除完全重复的值；`--no-global` 可跳过全局配置。

## 程序级配置（与权限配置分离）

`~/.config/cwrap/config.toml` 用于指定外部工具的可执行路径，
未配置时按 PATH 查找默认命令：

```toml
# cwrap 程序级配置（~/.config/cwrap/config.toml）
bwrap_path = "/usr/local/bin/bwrap"           # 默认 "bwrap"
xdg_dbus_proxy_path = "/opt/bin/xdg-dbus-proxy" # 默认 "xdg-dbus-proxy"
# flatpak-xdg-utils 的 xdg-open 路径（--allow portal 时覆盖容器内
# /usr/bin/xdg-open）；留空则自动探测 lib/libexec/lib64 等发行版布局，
# 全部未命中时打印警告
# xdg_open_path = "/usr/libexec/flatpak-xdg-utils/xdg-open"
```

## 参数传递方式

bwrap 与 xdg-dbus-proxy 的全部参数均经 **fd 传递**，彻底规避 ARG_MAX，
参数也不再暴露在 `/proc/<pid>/cmdline` 中：

- **bwrap**：`bwrap --args FD -- 命令 [参数...]`——fd 内容为 **NUL 分隔的选项**；
  受 bwrap 语义限制（fd 内容遇 `--` 即停止解析且其后被丢弃），`--` 与
  命令必须留在命令行（bubblejail 同款方式）；
- **xdg-dbus-proxy**：`xdg-dbus-proxy --fd=3 --args=4`——总线地址、socket
  路径、`--filter` 与全部规则均 NUL 分隔后进 fd。

## 架构

```
cwrap run（单进程，无守护进程）
   ├─ 纯 Go cBPF 生成 → memfd → --seccomp FD
   ├─ xdg-dbus-proxy（默认零规则；portal 场景由 bwrap 包装运行）
   ├─ bwrap（最小 rootfs / 隔离 HOME / 按授权挂载）
   └─ 生命周期：bwrap 带 --die-with-parent（PR_SET_PDEATHSIG），内核保证
      cwrap 退出（含 SIGKILL）即依序 SIGKILL monitor 与沙箱进程
```

### 持久化运行目录与实例注册表

每个配置占用一个持久化目录，目录名与伪造 `.flatpak-info` 的应用名
（`flatpakAppName`）一致；单次运行的 socket 目录以 instanceID 命名：

```
$XDG_RUNTIME_DIR/cwrap/
└── org.cwrap.App.demo/            # 持久化配置目录（跨运行保留）
    ├── instances.json             # instanceID -> {pid, start, app} 映射表
    ├── .lock                      # 注册表 flock（并发启动/退出串行化）
    └── <instanceID>/              # 单次运行 socket 目录（session/system/proxy.log）
```

- 每次通过同一配置启动沙箱，先在锁内清扫残留：映射表中 PID 已死
  （starttime 校验防 PID 复用）的实例目录与表外孤儿目录；
- 正常退出注销自身条目并删除实例目录；异常退出的残留由下次启动兜底；
- `ps`/`kill`/`clean` 直接读写该注册表，无需任何常驻进程。

## 测试

```sh
./scripts/smoke-test.sh    # 需要 bwrap（可经 BWRAP_DIR 指定自编译路径）
go test ./internal/...
```
