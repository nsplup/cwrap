package main

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"

	"cwrap/internal/seccomp"
)

type sockFilter struct {
	Code, Jt, Jf uint8
	K            uint32
}

type sockFprog struct {
	Len    uint16
	Filter *sockFilter
}

func main() {
	// 生成 dump: seccompcheck gen medium|high [--sync] /tmp/prog.bpf
	if len(os.Args) >= 4 && os.Args[1] == "gen" {
		syncBlock := false
		rest := os.Args[2:]
		if len(rest) == 3 && rest[1] == "--sync" {
			syncBlock = true
			rest = []string{rest[0], rest[2]}
		}
		prog, err := seccomp.Generate(rest[0], nil, false, syncBlock)
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(rest[1], prog, 0o644); err != nil {
			panic(err)
		}
		fmt.Printf("已写入 %s（%d 字节，%d 条指令）\n", rest[1], len(prog), len(prog)/8)
		return
	}

	// 安装测试: seccompcheck /tmp/prog.bpf
	if len(os.Args) < 2 {
		fmt.Println("用法: seccompcheck <prog.bpf>  |  seccompcheck generate <low|medium|high> <out.bpf>")
		os.Exit(2)
	}
	prog, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Printf("字节数=%d 指令数=%d 8对齐=%v\n", len(prog), len(prog)/8, len(prog)%8 == 0)
	if len(prog) == 0 || len(prog)%8 != 0 {
		fmt.Println("程序为空或未对齐 → 这就是 EINVAL 的原因")
		os.Exit(1)
	}

	insns := make([]sockFilter, len(prog)/8)
	for i := range insns {
		b := prog[i*8 : i*8+8]
		insns[i] = sockFilter{b[0], b[1], b[2],
			uint32(b[4]) | uint32(b[5])<<8 | uint32(b[6])<<16 | uint32(b[7])<<24}
	}

	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Println("PR_SET_NO_NEW_PRIVS 失败:", err)
		os.Exit(1)
	}
	fprog := sockFprog{Len: uint16(len(insns)), Filter: &insns[0]}
	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER,
		uintptr(unsafe.Pointer(&fprog)), 0, 0); err != nil {
		fmt.Println("prctl 返回:", err, "→ 程序本身非法，检查 BPF 生成逻辑")
		os.Exit(1)
	}
	fmt.Println("安装成功 → 程序合法，问题出在 fd 传递链路")
}
