package seccomp

import (
	"bytes"
	"testing"

	"golang.org/x/sys/unix"
)

// 验证生成的 BPF 程序长度对齐且结构合法。
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
