# cwrap 权限模型手册

cwrap 的权限语义对齐 Flatpak，但表达更直白：**默认零权限**，任何能力都必须
通过 FLAG 或 TOML 配置显式授予。配置加载顺序：

```
~/.config/cwrap/cwrap.toml（全局默认）
  < ~/.config/cwrap/apps/<APP>.toml（应用配置）
    < 命令行 FLAG（逐项覆盖）
```

## 权限一览

| 权限域 | FLAG | 取值 | 说明 |
|---|---|---|---|
| 应用标识 | `--app NAME` | 任意名称 | 决定 HOME 目录与配置文件，必需 |
| HOME | `--home PATH` | 绝对路径 | 覆盖默认 `$HOME/.var/sandbox/<APP>` |
| 共享 | `--share` | `network` `ipc` | network 同时放开 /etc/resolv.conf 读取 |
| socket | `--socket` | `x11` `wayland` `pulseaudio` `pipewire` `cups` `pcsc` `ssh-agent` | 只读挂载对应 socket |
| 设备 | `--device` | `dri` `kvm` `all` | 默认仅有 null/zero/urandom/tty 等最小 /dev |
| 文件系统 | `--fs SPEC` | `rw:PATH` `ro:PATH` | PATH 支持绝对路径与 flatpak 关键字（见下节） |
| /tmp | `--tmp MODE` | `sandbox`（默认） `sandbox:BASE` `tmpfs` `host` `/path` | 见下节 |
| 特性 | `--allow` | `devel` `multiarch` | devel 放行调试所需 seccomp 权限 |
| D-Bus | `--dbus SPEC` | `session.talk=N` `session.own=N` `system.talk=N` `system.own=N` | 默认零放行 |
| seccomp | `--seccomp LEVEL` | `low` `medium` `high` | 见下节 |
| syscall | `--allow-syscall` | syscall 名 | 向任意等级追加白名单 |
| 环境 | `--env K=V` | 任意 | 注入环境变量 |

环境变量默认全部擦除，仅保留：`PATH`、`TERM`、`LANG`、`HOME`、`USER`、
`LOGNAME`、`XDG_RUNTIME_DIR`；`DISPLAY` 仅在授予 `socket=x11` 时注入，
`WAYLAND_DISPLAY` 仅在授予 `socket=wayland` 时注入，以此类推。

## 文件系统授权（--fs）

PATH 支持以下 Flatpak 风格关键字（展开为宿主真实路径后按 `ro:`/`rw:` 挂载）：

| 关键字 | 展开为 |
|---|---|
| `home`、`~`、`~/sub` | 用户 HOME（`$HOME`） |
| `host` | 宿主全部一级目录；自动跳过 `/proc` `/sys` `/dev` `/usr` `/etc` `/run`（基线已处理）与 `/tmp`（由 `--tmp` 管辖） |
| `host-os` | `/usr` |
| `host-etc` | `/etc` |
| `xdg-config[/sub]` | `$XDG_CONFIG_HOME`（默认 `$HOME/.config`） |
| `xdg-data[/sub]` | `$XDG_DATA_HOME`（默认 `$HOME/.local/share`） |
| `xdg-cache[/sub]` | `$XDG_CACHE_HOME`（默认 `$HOME/.cache`） |
| `xdg-run[/sub]` | `$XDG_RUNTIME_DIR`（默认 `/run/user/<uid>`） |
| `xdg-desktop` `xdg-documents` `xdg-download` `xdg-music` `xdg-pictures` `xdg-public-share` `xdg-templates` `xdg-videos` | XDG 用户目录，按 `user-dirs.dirs` 解析（兼容中文目录名），未配置回退 `$HOME/<英文>` |

尾缀 `?`（如 `ro:~/project?`）表示目标不存在时不报错（使用 `--bind-try`）。
裸 `/` 仍被禁止（完整宿主请用关键字 `host` 逐级授予）。

## /tmp 处理（--tmp）

| 取值 | 行为 |
|---|---|
| `sandbox`（默认） | daemon 在宿主创建私有目录 `$TMPDIR/.cwrap-tmpdir-<uid>/<app>-<id>`，bind 为沙箱 `/tmp`；**退出后由 daemon 清理**（对齐 sas.sh `SHARE_APP_TMPDIR=0` 分支语义） |
| `sandbox:BASE` | 同上，但私有目录放在 `BASE`（绝对路径）下，同样自动清理 |
| `tmpfs` | 全空 `--tmpfs /tmp` |
| `host` | `--bind /tmp /tmp` 完整访问宿主 /tmp |
| `/some/path` | 把宿主 `/some/path` bind 为沙箱 `/tmp`（用户自管，不自动清理） |

**与 --fs 的去重**：`--tmp` 已接管 `/tmp` 后，`--fs` 中指向 `/tmp` 本身的授权项
会被过滤并警告；`tmp=host` 时 `/tmp` 子路径同样被过滤（宿主 `/tmp` 已整体可见，
ro 收窄失效）。警告会引导改用 `--tmp` 的自定义路径形式。`socket=x11` 的
`/tmp/.X11-unix` 挂载在 `tmp=host` 时跳过（已随 `/tmp` 可见，代价是该 socket
随 `/tmp` 变为可写，与 Flatpak 行为一致）。

## seccomp 等级

严格度递增，默认 `medium`：

| 等级 | 机制 | 内容 |
|---|---|---|
| `low` | 黑名单（最小集） | bpf、kexec_load、kexec_file_load、init_module、finit_module、delete_module、swapon、swapoff、reboot、acct |
| `medium` | 黑名单（flatpak 默认级） | low 全部 + ptrace、process_vm_readv/writev、keyctl、add_key、request_key、perf_event_open、setns、fanotify_init/mark、lookup_dcookie、open_by_handle_at、name_to_handle_at、clock_settime、settimeofday、adjtimex、iopl、ioperm、unshare、pivot_root、uselib |
| `high` | 默认拒绝 + 白名单 | 仅放行常规用户态集合（文件/进程/内存/网络/IPC/时钟），**附 W^X 保护** |

- **W^X 保护（仅 `high`）**：禁止创建同时具有 WRITE+EXEC 的内存映射
  （mmap/mprotect/pkey_mprotect）；`low`/`medium` 黑名单模式不做该检查。
- **`--allow devel`（对齐 Flatpak devel 语义）**：
  - `medium`：从黑名单剔除调试所需的 `ptrace`、`perf_event_open`；
  - `high`：白名单追加 `ptrace`、`perf_event_open`，并解除 W^X 检查。
- `--allow-syscall NAME` 在任意等级上追加放行；与等级集合叠加生效。
- BPF 程序由 cwrap 在内存中生成（纯 Go，无 libseccomp 依赖），经 memfd
  以文件描述符传给 `bwrap --seccomp`，不落盘。

基线 bwrap 参数额外包含 `--cap-drop ALL`（沙箱内进程不保留任何 Linux capability）。

## D-Bus

- 未授予任何 `--dbus` 权限时**不启动代理**，沙箱内没有总线可用。
- 授予后由 `xdg-dbus-proxy` 接管，`--filter` 生效且**默认零放行规则**，
  只有显式给出的 talk/own 名字被加入白名单。
- 代理 socket 写入 `$XDG_RUNTIME_DIR/cwrap/<时间戳>/session|system`，
  运行结束后由 cwrapd 清理。
- 沙箱内地址固定为 `unix:path=/run/cwrap/sessionBus|systemBus`。

## 已知限制（与 Flatpak 一致或明示不做）

- **X11 没有逐窗口权限**：授予 `socket=x11` 即等于信任该应用对 X 服务器的
  全部操作；需要细粒度隔离请使用 Wayland。
- 可执行文件自动挂载只做一层解析（脚本会连带其 shebang 解释器）；
  若二进制动态链接了挂载范围之外的私有库，请用 `--fs ro:PATH` 手动补充。
- `high` 级白名单目前按 amd64 构建生成；其他架构请使用 low/medium，
  或自行通过 `--allow-syscall` 补充。
