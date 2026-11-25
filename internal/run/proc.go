package run

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// procStartTicks 读取 /proc/<pid>/stat 的 starttime（第 22 字段，clock tick）。
// 进程存活期间该值不变，是区分"PID/pgid 被内核回收复用"的唯一可靠依据。
func procStartTicks(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// comm 可含空格与括号，从最后一个 ')' 之后切分
	i := bytes.LastIndexByte(data, ')')
	if i < 0 || i+2 > len(data) {
		return 0, fmt.Errorf("stat 格式异常")
	}
	fields := strings.Fields(string(data[i+2:])) // fields[0] = state(第3字段)
	if len(fields) < 20 {
		return 0, fmt.Errorf("stat 字段不足")
	}
	return strconv.ParseUint(fields[19], 10, 64) // 第22字段 => fields[19]
}

// sandboxRef 标识一个沙箱进程组（bwrap 自成组长，pgid == bwrap pid）。
type sandboxRef struct {
	pgid       int
	startTicks uint64 // bwrap 的 /proc starttime，供 killGroupSafe 校验 pgid 归属
}

// killGroupSafe 向沙箱进程组发信号。发送前用 starttime 校验 pgid 仍属于
// 当初启动的 bwrap，防止组退出后 pgid 被复用导致误杀。
func killGroupSafe(e *sandboxRef, sig syscall.Signal) {
	if e == nil || e.pgid <= 0 {
		return
	}
	if e.startTicks == 0 {
		syscall.Kill(-e.pgid, sig) // 启动瞬间没读到：回退直发，保可用性
		return
	}
	cur, err := procStartTicks(e.pgid)
	if err != nil || cur != e.startTicks {
		return // 组已退出或 pgid 已被复用：不补刀
	}
	syscall.Kill(-e.pgid, sig)
}
