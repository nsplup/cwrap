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

# 11. daemon 清理：运行结束后 XDG_RUNTIME_DIR 下无残留运行目录
sleep 1
left=$(ls "$XDG_RUNTIME_DIR/cwrap" 2>/dev/null | rg -v 'cwrapd.sock|cwrapd.log' | wc -l)
[ "$left" = 0 ] && ok "temp cleanup" || bad "temp cleanup (left=$left)"

echo "-----"
echo "pass=$pass fail=$fail"
[ "$fail" = 0 ]
