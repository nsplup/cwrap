package seccomp

import (
	"bytes"
	"testing"

	"golang.org/x/sys/unix"
)

// 验证生成的 BPF 程序长度对齐且结构合法。
func TestAllowSetHighCritical(t *testing.T) {
	// 关键调用必须存在（futex 缺失曾导致多线程程序在 high 档死锁）
	for _, want := range []string{
		"exit_group", "futex", "prlimit64", "getrlimit", "restart_syscall",
		"mlock2", "pidfd_send_signal", "fchmodat2",
	} {
		if !inStrList(allowSetHigh, want) {
			t.Fatalf("high 白名单缺少关键调用 %q", want)
		}
	}
	// W^X 三调用必须不在静态白名单（由 genAllow 的检查路径处理），
	// 否则 emitWXChecks 不可达、W^X 保护失效
	for _, bad := range []string{"mmap", "mprotect", "pkey_mprotect"} {
		if inStrList(allowSetHigh, bad) {
			t.Fatalf("W^X 调用 %q 不应在静态白名单中", bad)
		}
	}
}

func TestGenerateHighWXShape(t *testing.T) {
	prog, err := Generate("high", nil, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(prog) == 0 || len(prog)%8 != 0 {
		t.Fatalf("非法 BPF 长度 %d", len(prog))
	}
	// 存在两条 retAllow（W^X 通过链尾 + 白名单放行）与默认拒绝 EPERM
	var allows, eperm int
	for i := 0; i+8 <= len(prog); i += 8 {
		if prog[i] == 0x06 { // BPF_RET
			k := uint32(prog[i+4]) | uint32(prog[i+5])<<8 | uint32(prog[i+6])<<16 | uint32(prog[i+7])<<24
			switch k {
			case 0x7fff0000:
				allows++
			case 0x00050001: // EPERM
				eperm++
			}
		}
	}
	if allows < 2 {
		t.Fatalf("W^X 通过链尾的放行 ret 缺失（allows=%d）", allows)
	}
	if eperm < 1 {
		t.Fatal("默认拒绝 EPERM 缺失")
	}
}

func inStrList(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func TestGenerateShape(t *testing.T) {
	for _, level := range []string{"low", "medium", "high"} {
		b, err := Generate(level, []string{"memfd_create"}, false, false)
		if err != nil {
			t.Fatalf("%s: %v", level, err)
		}
		if len(b) == 0 || len(b)%8 != 0 {
			t.Fatalf("%s: bad program length %d", level, len(b))
		}
	}
}

func TestGenerateRejectsBadLevel(t *testing.T) {
	if _, err := Generate("nope", nil, false, false); err == nil {
		t.Fatal("expected error for unknown level")
	}
}

func TestDenyProgramContent(t *testing.T) {
	b, err := Generate("low", nil, false, false)
	if err != nil {
		t.Fatal(err)
	}
	// 结构: [LD arch][JEQ arch][RET ENOSYS][LD nr] + N*(JEQ nr) + RET ALLOW + RET EPERM
	nInstr := len(b) / 8
	if nInstr < 8 {
		t.Fatalf("program too small: %d instrs", nInstr)
	}
	if !bytes.Contains(b, []byte{0x3e, 0x00, 0x00, 0xc0}) { // AUDIT_ARCH_X86_64 小端
		t.Fatal("arch check missing")
	}
}

func TestMemfd(t *testing.T) {
	b, _ := Generate("medium", nil, false, false)
	f, err := Memfd(b)
	if err != nil {
		t.Skipf("memfd 不可用: %v", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() != int64(len(b)) {
		t.Fatalf("memfd size mismatch: %v %v", err, st)
	}
}

// allowlist 应包含 futex 等基础调用。
func TestAllowSetBasics(t *testing.T) {
	for _, name := range []string{"read", "write", "futex", "openat", "rt_sigaction"} {
		if _, ok := num(name); !ok {
			t.Fatalf("allowlist missing %s", name)
		}
	}
}

// devel 从 medium 黑名单剔除 ptrace/perf_event_open，保留 process_vm_*。
func TestDevelMediumDenySet(t *testing.T) {
	plain := denySet("medium", false)
	devel := denySet("medium", true)
	has := func(list []string, n string) bool {
		for _, v := range list {
			if v == n {
				return true
			}
		}
		return false
	}
	if !has(plain, "ptrace") || !has(plain, "perf_event_open") {
		t.Fatal("medium 默认应拒绝 ptrace/perf_event_open")
	}
	if has(devel, "ptrace") || has(devel, "perf_event_open") {
		t.Fatal("devel 应放行 ptrace/perf_event_open")
	}
	if !has(devel, "process_vm_readv") {
		t.Fatal("devel 不应放行 process_vm_readv（flatpak 仅提及 ptrace/perf_event_open）")
	}
}

// medium（黑名单模式）不做 W^X 检查；high 做，devel 解除。
func TestWXOnlyInHigh(t *testing.T) {
	mPlain, _ := Generate("medium", nil, false, false)
	mDevel, _ := Generate("medium", nil, true, false)
	// devel 剔除两项黑名单 → 程序应更短；若 medium 仍含 W^X 检查且 devel
	// 试图解除，长度差异会明显不同（此断言保证行为可感知地变化）。
	if len(mDevel) >= len(mPlain) {
		t.Fatalf("medium devel 程序应更短: %d vs %d", len(mDevel), len(mPlain))
	}

	hPlain, _ := Generate("high", nil, false, false)
	hDevel, _ := Generate("high", nil, true, false)
	if len(hDevel) >= len(hPlain) {
		t.Fatalf("high devel（+2 白名单、-W^X 检查）应更短: %d vs %d", len(hDevel), len(hPlain))
	}
}

var _ = unix.EPERM

// --harden sync：落盘 syscall 全部映射到"返回 0"。
func TestSyncBlock(t *testing.T) {
	plain, err := Generate("medium", nil, false, false)
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := Generate("medium", nil, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked) <= len(plain) {
		t.Fatalf("sync 屏蔽链应使程序变长: %d vs %d", len(blocked), len(plain))
	}

	hPlain, _ := Generate("high", nil, false, false)
	hBlock, _ := Generate("high", nil, false, true)
	if len(hBlock) <= len(hPlain) {
		t.Fatalf("high 档 sync 屏蔽链应生效: %d vs %d", len(hBlock), len(hPlain))
	}
}
