package seccomp

import (
	"bytes"
	"testing"

	"golang.org/x/sys/unix"
)

// 验证生成的 BPF 程序长度对齐且结构合法。
func TestGenerateShape(t *testing.T) {
	for _, level := range []string{"low", "medium", "high"} {
		b, err := Generate(level, []string{"memfd_create"}, false)
		if err != nil {
			t.Fatalf("%s: %v", level, err)
		}
		if len(b) == 0 || len(b)%8 != 0 {
			t.Fatalf("%s: bad program length %d", level, len(b))
		}
	}
}

func TestGenerateRejectsBadLevel(t *testing.T) {
	if _, err := Generate("nope", nil, false); err == nil {
		t.Fatal("expected error for unknown level")
	}
}

func TestDenyProgramContent(t *testing.T) {
	b, err := Generate("low", nil, false)
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
	b, _ := Generate("medium", nil, false)
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

var _ = unix.EPERM
