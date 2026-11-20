# cwrap

**cwrap** 是面向 [bubblewrap](https://github.com/containers/bubblewrap) 的上层包装器（Go CLI），
权限模型看齐 [Flatpak](https://github.com/flatpak/flatpak)，但语义更直白：

- **默认零权限**——无网络、无 X11/Wayland、无 D-Bus、HOME 完全隔离、seccomp 最严格档可用；
- 所有能力通过 FLAG 或 TOML 配置文件**显式授权**；
- 守护进程 `cwrapd` 管理子进程生命周期、转发 stdio/信号/退出码、自动清理临时文件；
- seccomp BPF 过滤器由 cwrap **纯 Go 内存生成**，经 memfd 以 FD 传给 `bwrap --seccomp`；
- D-Bus 由 `xdg-dbus-proxy` 接管，**默认零放行规则**，socket 存放于
  `$XDG_RUNTIME_DIR/cwrap/<时间戳>/`。

依赖运行时：`bwrap`（必装）、`xdg-dbus-proxy`（仅使用 D-Bus 权限时需要）。
无需 root（bubblewrap 走非特权 user namespace）。

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

# /tmp 三档：私有目录（默认，退出由 daemon 清理）/ 全空 tmpfs / 宿主 /tmp
cwrap run --app demo --tmp tmpfs -- /usr/bin/myapp
cwrap run --app demo --tmp host -- /usr/bin/myapp
cwrap run --app demo --tmp /mnt/share/tmp -- /usr/bin/myapp

# fs 授权支持 flatpak 关键字展开（home/host/xdg-* 等，? 表示不存在不报错）
cwrap run --app demo --fs ro:xdg-download? --fs rw:~/project -- /usr/bin/myapp

# 把本次授权固化为 demo 的配置文件
cwrap run --app demo --share network --persist -- /usr/bin/myapp
```

## 命令

| 命令 | 说明 |
|---|---|
| `cwrap run [FLAGS] -- CMD [ARGS…]` | 在沙箱中运行命令 |
| `cwrap permission show [APP] [FLAGS…]` | 显示合并后的有效权限 |
| `cwrap permission export APP [FLAGS…]` | 把 FLAGS/全局合并结果写入应用配置 |
| `cwrap ps` | 列出运行中的沙箱 |
| `cwrap kill <ID\|APP>` | 终止沙箱 |
| `cwrap clean` | 清扫陈旧的运行目录 |
| `cwrap daemon` | 手动启动守护进程（通常自动拉起） |

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
allow = []
fs = ["ro:/opt/data", "ro:xdg-download?"]   # 支持 flatpak 关键字，? = 不存在不报错
dbus = [
  "session.talk=org.freedesktop.Notifications",
  "session.own=org.example.Demo",
]
allow_syscalls = []
env = ["MYAPP_DEBUG=1"]
# home = "/srv/sandbox/demo"   # 自定义隔离目录
```

优先级：全局 < 应用 < 命令行 FLAG。
标量字段逐级覆盖；列表字段累加并去除完全重复的值；`--no-global` 可跳过全局配置。

## 架构

```
cwrap run (CLI)
   │  UDS + SCM_RIGHTS(stdio) + JSON
   ▼
cwrapd（daemon，同二进制，空闲 30s 自动退出）
   ├─ 纯 Go cBPF 生成 → memfd → --seccomp FD
   ├─ xdg-dbus-proxy（默认零规则，socket 在 XDG_RUNTIME_DIR）
   └─ bwrap（最小 rootfs / 隔离 HOME / 按授权挂载）
```

## 测试

```sh
./scripts/smoke-test.sh    # 需要 bwrap（可经 BWRAP_DIR 指定自编译路径）
go test ./internal/...
```
