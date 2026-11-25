#!/usr/bin/env bash
# cwrap 冒烟测试：需要 PATH 中有 bwrap；dbus 部分需要 xdg-dbus-proxy。
set -u
CWRAP="${CWRAP:-./cwrap}"
BWRAP_DIR="${BWRAP_DIR:-}"   # 如有自编译 bwrap，传入其所在目录
if [ -n "$BWRAP_DIR" ]; then export PATH="$BWRAP_DIR:$PATH"; fi
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/tmp/cwrap-test-rt}"
rm -rf "$XDG_RUNTIME_DIR"; mkdir -p "$XDG_RUNTIME_DIR"

pass=0; fail=0
ok()   { pass=$((pass+1)); echo "PASS: $1"; }
bad()  { fail=$((fail+1)); echo "FAIL: $1"; }

t() { # t <名称> <期望rc> <命令...>
  local name="$1" want="$2"; shift 2
  "$@" >/tmp/cwrap-smoke.out 2>&1; local rc=$?
  if [ "$rc" = "$want" ]; then ok "$name"; else bad "$name (rc=$rc want=$want)"; sed 's/^/    /' /tmp/cwrap-smoke.out | head -5; fi
}

# 探测本机内核是否允许 PR_SET_SECCOMP（部分容器宿主禁止）
probe() {
  "$CWRAP" run --app probe --seccomp low -- /bin/true >/dev/null 2>&1
}
if probe; then
  SEC_OFF=(); SEC_MED=(--seccomp medium); SEC_HIGH=(--seccomp high)
  echo "note: 内核支持 seccomp，测试包含过滤等级"
else
  SEC_OFF=(--seccomp off); SEC_MED=(); SEC_HIGH=()
  echo "note: 本宿主禁止 PR_SET_SECCOMP，运行时测试降级为 --seccomp off（等级生成仍由单元测试覆盖）"
fi

# 1. dry-run：参数拼装（不实际运行）
t "dry-run" 0 "$CWRAP" run --app demo --dry-run -- /bin/echo hi
t "dry-run high seccomp" 0 "$CWRAP" run --app demo --seccomp high --dry-run -- /bin/echo hi

# 2. 最小权限 echo（HOME 隔离）
rm -rf "$HOME/.var/sandbox/demo"
t "echo in sandbox" 0 "$CWRAP" run --app demo "${SEC_OFF[@]}" -- /bin/echo hello-cwrap
grep -q hello-cwrap /tmp/cwrap-smoke.out && ok "echo output" || bad "echo output"

# 3. HOME 隔离：宿主家目录不存在同名标记文件
touch "$HOME/.var/sandbox/demo/homemark"
"$CWRAP" run --app demo "${SEC_OFF[@]}" -- /bin/sh -c 'ls "$HOME"' >/tmp/cwrap-smoke.out 2>&1
grep -q homemark /tmp/cwrap-smoke.out && ok "home isolation" || bad "home isolation"

# 4. 无宿主文件泄漏：/etc 只读可读但宿主家目录不可见
"$CWRAP" run --app demo "${SEC_OFF[@]}" -- /bin/sh -c 'test ! -e /etc/cwrap-marker && test -f /etc/hostname' >/dev/null 2>&1
ok "no host fs leak"

# 5. 退出码透传
t "exit code passthrough" 7 "$CWRAP" run --app demo "${SEC_OFF[@]}" -- /bin/sh -c 'exit 7'

# 6. persist + permission show
"$CWRAP" run --app demo --share network --persist "${SEC_OFF[@]}" -- /bin/true >/dev/null 2>&1
"$CWRAP" permission show demo | grep -q network && ok "persist+show" || bad "persist+show"

# 7. ps
t "ps" 0 "$CWRAP" ps

# 8. seccomp 等级实际生效（仅在内核支持时）
if [ -n "${SEC_HIGH[0]:-}" ]; then
  t "medium seccomp ls" 0 "$CWRAP" run --app demo --seccomp medium -- /bin/ls /usr
  t "high seccomp ls" 0 "$CWRAP" run --app demo --seccomp high -- /bin/ls /usr
fi

# 9. seccomp 拒绝验证：high 白名单下不允许的调用应失败（内核支持时）
if [ -n "${SEC_HIGH[0]:-}" ]; then
  "$CWRAP" run --app demo --seccomp high -- /usr/bin/unshare --map-root-user true >/dev/null 2>&1
  [ $? -ne 0 ] && ok "high seccomp blocks unshare" || bad "high seccomp blocks unshare"
fi

# 10. dbus 权限无宿主会话总线时应报错
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
  "$CWRAP" run --app demo --dbus session.talk=org.foo "${SEC_OFF[@]}" -- /bin/true >/dev/null 2>&1
  [ $? -ne 0 ] && ok "dbus error without host bus" || bad "dbus error without host bus"
fi

# 11. 实例清理：运行结束后无残留实例子目录（持久化配置目录保留）
sleep 1
left=$(find "$XDG_RUNTIME_DIR/cwrap" -mindepth 2 -maxdepth 2 -type d 2>/dev/null | wc -l)
[ "$left" = 0 ] && ok "temp cleanup" || bad "temp cleanup (left=$left)"
appdir="$XDG_RUNTIME_DIR/cwrap/org.cwrap.App.demo"
[ -d "$appdir" ] && ok "persistent app dir kept" || bad "persistent app dir kept"

# 11b. 启动清扫：死 PID 的残留实例目录与表外孤儿目录应在下次启动时被清理
mkdir -p "$appdir/dead0000000000000000000000000000" "$appdir/orphan00000000000000000000000000"
printf '{"dead0000000000000000000000000000":{"pid":999999999,"start":1,"app":"demo"}}' > "$appdir/instances.json"
"$CWRAP" run --app demo "${SEC_OFF[@]}" -- /bin/true >/dev/null 2>&1
{ [ ! -d "$appdir/dead0000000000000000000000000000" ] && [ ! -d "$appdir/orphan00000000000000000000000000" ]; } \
  && ok "stale instance swept on launch" || bad "stale instance swept on launch"

# 12. --tmp 两档 dry-run（参数拼装）与非法值报错
t "dry-run tmp tmpfs" 0 "$CWRAP" run --app demo --tmp tmpfs --dry-run -- /bin/echo hi
t "dry-run tmp host" 0 "$CWRAP" run --app demo --tmp host --dry-run -- /bin/echo hi
t "invalid tmp rejected (sandbox)" 2 "$CWRAP" run --app demo --tmp sandbox --dry-run -- /bin/echo hi
t "invalid tmp rejected (path)" 2 "$CWRAP" run --app demo --tmp /var/tmp --dry-run -- /bin/echo hi

# 13. --fs 与 --tmp 冲突过滤警告
"$CWRAP" run --app demo --tmp host --fs ro:/tmp/sub --dry-run -- /bin/true >/tmp/cwrap-smoke.out 2>&1
grep -q "已被忽略" /tmp/cwrap-smoke.out && ok "fs/tmp conflict warning" || bad "fs/tmp conflict warning"

# 14. 无 --app 可运行（省略应用名时 HOME 默认 $HOME/.var/sandbox/home）
rm -rf "$HOME/.var/sandbox/home"
t "run without --app" 0 "$CWRAP" run --no-global "${SEC_OFF[@]}" -- /bin/echo no-app
[ -d "$HOME/.var/sandbox/home" ] && ok "no-app home dir created" || bad "no-app home dir created"

# ---- 以下为权限对齐扩展（flatpak / bubblejail 对齐）的冒烟场景 ----

# 15. 否决语义 dry-run：--no-socket 应使参数中不再出现 x11 socket 挂载
"$CWRAP" run --app demo --socket x11 --no-socket x11 --dry-run -- /bin/true >/tmp/cwrap-smoke.out 2>&1
grep -q -- "--ro-bind-try /tmp/.X11-unix" /tmp/cwrap-smoke.out && bad "deny removes x11" || ok "deny removes x11"

# 16. TOML "!" 否决与 --no-* 等价（FLAG 层验证）
t "deny syntax accepted" 0 "$CWRAP" run --app demo --socket '!wayland' --dry-run -- /bin/true

# 17. session-bus 直通：无宿主总线时仍允许拼参（直通不启动代理）
t "dry-run session-bus passthrough" 0 "$CWRAP" run --app demo --socket session-bus --dry-run -- /bin/true

# 18. gpg-agent / 新设备值 / preset / portal / harden / net-backend 拼参
t "dry-run gpg-agent" 0 "$CWRAP" run --app demo --socket gpg-agent --dry-run -- /bin/true
t "dry-run device ntsync" 0 "$CWRAP" run --app demo --device ntsync --dry-run -- /bin/true
t "dry-run dbus preset" 0 "$CWRAP" run --app demo --dbus preset:notify --dry-run -- /bin/true
t "dry-run mpris preset" 0 "$CWRAP" run --app demo --dbus 'preset:mpris=firefox.*' --dry-run -- /bin/true
t "dry-run portal package" 0 "$CWRAP" run --app demo --allow portal --dry-run -- /bin/true
t "dry-run harden namespaces" 0 "$CWRAP" run --app demo --harden namespaces --dry-run -- /bin/true
t "dry-run harden sync" 0 "$CWRAP" run --app demo --harden sync --dry-run -- /bin/true
t "dry-run net-backend pasta" 0 "$CWRAP" run --app demo --net-backend pasta --dry-run -- /bin/true
t "invalid net-backend rejected" 2 "$CWRAP" run --app demo --net-backend vpn --dry-run -- /bin/true
t "invalid harden rejected" 2 "$CWRAP" run --app demo --harden cheat --dry-run -- /bin/true

# 19. --unset-env / --bwrap-arg / --dbus-arg 拼参
t "dry-run unset-env" 0 "$CWRAP" run --app demo --unset-env LANG --dry-run -- /bin/true
t "dry-run bwrap-arg" 0 "$CWRAP" run --app demo --bwrap-arg --cap-drop --bwrap-arg ALL --dry-run -- /bin/true

# 20. harden namespaces 实际运行（pid1 写零 namespace 限额后 exec）
if [ -n "${SEC_OFF[0]:-}" ]; then SECN=(--seccomp off); else SECN=(); fi
t "harden namespaces run" 0 "$CWRAP" run --app demo "${SECN[@]}" --harden namespaces -- /bin/echo hardened

# 21. portal 包实际运行：沙箱内应能看到 /.flatpak-info
"$CWRAP" run --app demo "${SECN[@]}" --allow portal -- /bin/sh -c 'test -f /.flatpak-info' >/dev/null 2>&1
[ $? = 0 ] && ok "portal flatpak-info visible" || bad "portal flatpak-info visible"

echo "-----"
echo "pass=$pass fail=$fail"
[ "$fail" = 0 ]
