// Package seccomp 用纯 Go 生成供 bwrap --seccomp 使用的 classic BPF
// （cBPF）过滤程序，不依赖 libseccomp、不启用 cgo。
//
// 过滤等级语义（严格度递增）：
//
//	low    : 仅黑名单极小集（内核级高危：BPF、模块加载、kexec 等）
//	medium : flatpak 默认级别的黑名单（追加 ptrace 系、keyctl、userns 等）；
//	         --allow devel 时剔除调试所需的 ptrace/perf_event_open
//	high   : 默认拒绝 + 白名单（仅放行常规用户态运行所需集合）
//
// W^X 保护仅在 high 档生效：默认禁止 W+X 映射（mmap/mprotect/pkey_mprotect），
// --allow devel 可解除并放行 ptrace/perf_event_open；--allow-syscall 可向
// 任意等级追加白名单。
package seccomp

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// classic BPF 指令编码常量。
const (
	bpfLDABS = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJEQ   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfRET   = 0x06 // BPF_RET | BPF_K
	bpfAND   = 0x54 // BPF_ALU | BPF_AND | BPF_K
)

// seccomp_data 字段偏移。
const (
	offNR   = 0  // u32 nr
	offArch = 4  // u32 arch
	offArg2 = 32 // u64 args[2] 的低 32 位（小端），mmap/mprotect/pkey_mprotect 的 prot
)

const (
	retAllow = 0x7fff0000
	retErrno = 0x00050000

	// retErrnoZero 表示 SECCOMP_RET_ERRNO 且 errno = 0，
	// 对被拦截的调用表现为"成功并返回 0"。
	retErrnoZero = retErrno
)

const protWriteExec = 0x6 // PROT_WRITE(2) | PROT_EXEC(4)

type Instr struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

func (i Instr) bytes() []byte {
	return []byte{
		byte(i.Code), byte(i.Code >> 8), // u16 code，小端（当前所有 code < 0x100，高位恒 0）
		i.Jt, i.Jf,
		byte(i.K), byte(i.K >> 8), byte(i.K >> 16), byte(i.K >> 24), // u32 k，小端
	}
}

// denySet 返回某个等级的黑名单 syscall 名单（等级越高名单越长）。
// develOK（--allow devel）按 flatpak 语义放行调试工具所需的
// ptrace 与 perf_event_open（仅从 medium 黑名单中剔除）。
func denySet(level string, develOK bool) []string {
	low := []string{
		"bpf",
		"kexec_load", "kexec_file_load",
		"init_module", "finit_module", "delete_module",
		"swapon", "swapoff",
		"reboot", "acct",
	}
	if level == "low" {
		return low
	}
	medium := append(low, []string{
		"ptrace", "process_vm_readv", "process_vm_writev",
		"keyctl", "add_key", "request_key",
		"perf_event_open", "setns", "fanotify_init", "fanotify_mark",
		"lookup_dcookie", "open_by_handle_at", "name_to_handle_at",
		"clock_settime", "settimeofday", "adjtimex", "iopl", "ioperm",
		"unshare", // 替换 create_user_ns：同时覆盖 userns/mountns 等
		"pivot_root", "uselib",
	}...)
	if develOK {
		// flatpak 文档：devel 允许 ptrace() 与 perf_event_open() 等
		// 调试所需的系统调用
		medium = removeFromList(medium, "ptrace", "perf_event_open")
	}
	return medium // high 不走黑名单，占位
}

func removeFromList(list []string, names ...string) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		drop := false
		for _, n := range names {
			if v == n {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, v)
		}
	}
	return out
}

// allowSetHigh 是 high（默认拒绝）模式下的基础白名单：
// 常规用户态程序运行所需的调用集合。
var allowSetHigh = []string{
	// 进程基础
	"exit", "exit_group", "clone", "clone3", "fork", "vfork",
	"execve", "execveat", "wait4", "waitid", "kill", "tgkill",
	"getpid", "getppid", "gettid", "getuid", "geteuid", "getgid", "getegid",
	"getresuid", "getresgid", "getgroups", "setgroups", "setsid",
	"getpgid", "setpgid", "getpgrp", "getsid",
	"set_tid_address", "set_robust_list", "get_robust_list",
	"arch_prctl", "prctl", "capget", "capset",
	"sched_yield", "sched_getscheduler", "sched_setscheduler",
	"sched_getparam", "sched_setparam",
	"sched_getaffinity", "sched_setaffinity",
	"sched_getattr", "sched_setattr",
	"getpriority", "setpriority", "nice",
	"getrusage", "uname", "getrandom", "getcpu", "sysinfo",
	"pidfd_open", "pidfd_getfd", "close_range",
	// 信号
	"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "rt_sigpending",
	"rt_sigsuspend", "rt_sigtimedwait", "sigaltstack",
	"signal", "pause",
	// 内存
	"brk", "mmap", "munmap", "mremap", "mprotect", "madvise", "msync",
	"mincore", "mlock", "munlock", "membarrier", "rseq",
	"pkey_mprotect", "pkey_alloc", "pkey_free",
	// 文件
	"read", "write", "open", "openat", "openat2", "close",
	"stat", "fstat", "lstat", "newfstatat", "statx", "poll", "ppoll",
	"lseek", "pread64", "pwrite64", "readv", "writev",
	"access", "faccessat", "faccessat2",
	"dup", "dup2", "dup3", "fcntl",
	"ioctl",
	"mkdir", "mkdirat", "rmdir", "unlink", "unlinkat",
	"rename", "renameat", "renameat2",
	"link", "linkat", "symlink", "symlinkat",
	"readlink", "readlinkat", "chmod", "fchmod", "fchmodat",
	"chown", "fchown", "lchown", "fchownat",
	"umask", "getcwd", "chdir", "fchdir",
	"truncate", "ftruncate",
	"utime", "utimes", "utimensat", "futimesat",
	"getdents", "getdents64",
	"fsync", "fdatasync", "sync", "syncfs",
	"statfs", "fstatfs", "fadvise64", "fallocate",
	"sendfile", "copy_file_range", "splice", "vmsplice", "tee",
	"getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr",
	"setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr",
	"memfd_create",
	// 描述符 / 事件
	"pipe", "pipe2", "select", "pselect6",
	"epoll_create", "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait", "epoll_pwait2",
	"eventfd", "eventfd2",
	"signalfd", "signalfd4",
	"inotify_init", "inotify_init1", "inotify_add_watch", "inotify_rm_watch",
	"timerfd_create", "timerfd_settime", "timerfd_gettime",
	"flock",
	// 时间
	"time", "gettimeofday", "clock_gettime", "clock_getres",
	"clock_nanosleep", "nanosleep", "alarm",
	// 网络
	"socket", "socketpair", "connect", "accept", "accept4", "bind", "listen",
	"recvfrom", "recvmsg", "recvmmsg", "sendto", "sendmsg", "sendmmsg",
	"shutdown", "getsockname", "getpeername", "setsockopt", "getsockopt",
	"gethostname",
	// System V IPC（X11 MIT-SHM 等需要）
	"shmget", "shmat", "shmdt", "shmctl",
	"semget", "semop", "semtimedop", "semctl",
	"msgget", "msgrcv", "msgsnd", "msgctl",
}

// Generate 按等级与追加白名单生成 BPF 程序字节流。
//
// W^X 保护只作用于 high（默认拒绝）模式：命中 mmap/mprotect/pkey_mprotect
// 且 prot 同时含 W|X 时拒绝；develOK 为 true 时 high 不包含 W^X 检查，
// 并额外放行调试所需的 ptrace/perf_event_open（flatpak devel 语义）。
// low/medium 为黑名单模式，不做 W^X 检查（devel 仅影响 medium 黑名单内容）。
func Generate(level string, extraAllow []string, develOK, hardenSync bool) ([]byte, error) {
	switch level {
	case "low", "medium":
		return genDeny(denySet(level, develOK), hardenSync)
	case "high":
		names := append(append([]string{}, allowSetHigh...), extraAllow...)
		if develOK {
			names = append(names, "ptrace", "perf_event_open")
		}
		return genAllow(names, develOK, hardenSync)
	default:
		return nil, fmt.Errorf("未知 seccomp 等级 %q", level)
	}
}

// progHelp 组装辅助。
type progHelp struct {
	ins          []Instr
	patchDeny    []int // 需要跳到"最终拒绝 ret"的指令下标（patch Jt）
	patchAllow   []int // 需要跳到"最终放行 ret"的指令下标（patch Jt）
	patchSyncOK  []int // 需要跳到"假装成功 ret(0)"的指令下标（--harden sync）
	denyInstrAt  int
	allowInstrAt int
	syncOKAt     int
}

func (p *progHelp) emit(i Instr) int {
	p.ins = append(p.ins, i)
	return len(p.ins) - 1
}

func (p *progHelp) emitJumpToDeny(code uint16, k uint32) {
	idx := p.emit(Instr{Code: code, K: k})
	p.patchDeny = append(p.patchDeny, idx)
}

func (p *progHelp) emitJumpToAllow(code uint16, k uint32) {
	idx := p.emit(Instr{Code: code, K: k})
	p.patchAllow = append(p.patchAllow, idx)
}

func (p *progHelp) patch() {
	for _, i := range p.patchDeny {
		d := p.denyInstrAt - i - 1
		if d < 0 || d > 255 {
			panic(fmt.Sprintf("seccomp: BPF 跳转距离超界 (%d)，请拆分规则链", d))
		}
		p.ins[i].Jt = uint8(d)
	}
	for _, i := range p.patchAllow {
		d := p.allowInstrAt - i - 1
		if d < 0 || d > 255 {
			panic(fmt.Sprintf("seccomp: BPF 跳转距离超界 (%d)，请拆分规则链", d))
		}
		p.ins[i].Jt = uint8(d)
	}
	for _, i := range p.patchSyncOK {
		d := p.syncOKAt - i - 1
		if d < 0 || d > 255 {
			panic(fmt.Sprintf("seccomp: BPF 跳转距离超界 (%d)，请拆分规则链", d))
		}
		p.ins[i].Jt = uint8(d)
	}
}

// syncBlockSet 是 --harden sync（对齐 bubblejail filter_disk_sync 服务）
// 屏蔽的落盘调用集合：全部返回 0（假装成功，磁盘无实际写入）。
var syncBlockSet = []string{"sync", "fsync", "fdatasync", "syncfs", "sync_file_range", "msync"}

// emitSyncBlock 追加 sync 屏蔽链：命中即跳到"返回 0"。
func (p *progHelp) emitSyncBlock() {
	for _, name := range syncBlockSet {
		if nr, ok := num(name); ok {
			idx := p.emit(Instr{Code: bpfJEQ, Jf: 0, K: nr})
			p.patchSyncOK = append(p.patchSyncOK, idx)
		}
	}
}

// preamble 生成 arch 校验 + nr 载入。
func (p *progHelp) preamble() error {
	arch, ok := auditArch()
	if !ok {
		return fmt.Errorf("seccomp 过滤器当前仅支持 amd64/arm64 构建")
	}
	p.emit(Instr{Code: bpfLDABS, K: offArch}) // A = arch
	// 命中本机架构 → Jt=1 跳过 ENOSYS → 继续读 nr；
	// 其他架构（x32 等）→ Jf=0 → 返回 ENOSYS 伪装
	p.emit(Instr{Code: bpfJEQ, Jt: 1, K: arch})
	p.emit(Instr{Code: bpfRET, K: retErrno | uint32(unix.ENOSYS)})
	p.emit(Instr{Code: bpfLDABS, K: offNR}) // A = syscall nr
	return nil
}

// emitWXChecks 追加 W^X 检查：命中 mmap/mprotect/pkey_mprotect 且
// prot 同时含 W|X 时跳到拒绝，其余情况落到后续指令。
func (p *progHelp) emitWXChecks() {
	for _, name := range []string{"mmap", "mprotect", "pkey_mprotect"} {
		nr, ok := num(name)
		if !ok {
			continue
		}
		p.emit(Instr{Code: bpfJEQ, Jf: 3, K: nr}) // 未命中该调用 -> 跳过本组检查
		p.emit(Instr{Code: bpfLDABS, K: offArg2}) // A = prot 低 32 位
		p.emit(Instr{Code: bpfAND, K: protWriteExec})
		p.emitJumpToDeny(bpfJEQ, protWriteExec) // W|X 同时存在 -> 拒绝
	}
}

func genDeny(deny []string, hardenSync bool) ([]byte, error) {
	p := &progHelp{}
	if err := p.preamble(); err != nil {
		return nil, err
	}
	var nums []uint32
	for _, name := range deny {
		if nr, ok := num(name); ok {
			nums = append(nums, nr)
		}
	}
	for _, nr := range nums {
		// 命中黑名单 -> 跳到最终拒绝；未命中 -> 落到下一条
		idx := p.emit(Instr{Code: bpfJEQ, Jf: 0, K: nr})
		p.patchDeny = append(p.patchDeny, idx)
	}
	if hardenSync {
		p.emitSyncBlock()
	}
	// 黑名单模式不做 W^X 检查（仅 high 默认拒绝模式实施 W^X）
	p.emit(Instr{Code: bpfRET, K: retAllow})                                      // 默认放行
	p.denyInstrAt = p.emit(Instr{Code: bpfRET, K: retErrno | uint32(unix.EPERM)}) // 拒绝
	if hardenSync {
		p.syncOKAt = p.emit(Instr{Code: bpfRET, K: retErrnoZero}) // 假装成功（errno 0）
	}
	p.patch()
	return pack(p.ins), nil
}

func genAllow(allow []string, develOK, hardenSync bool) ([]byte, error) {
	p := &progHelp{}
	if err := p.preamble(); err != nil {
		return nil, err
	}
	for _, name := range allow {
		nr, ok := num(name)
		if !ok {
			continue
		}
		p.emitJumpToAllow(bpfJEQ, nr)
	}
	// 未命中白名单的调用此刻 A 仍是 nr 原值，
	// 在此做 W^X 检查（命中 mmap/mprotect/pkey_mprotect 且 W|X → 拒绝）
	if !develOK {
		p.emitWXChecks()
	}
	if hardenSync {
		p.emitSyncBlock()
	}
	p.denyInstrAt = p.emit(Instr{Code: bpfRET, K: retErrno | uint32(unix.EPERM)}) // 默认拒绝
	p.allowInstrAt = p.emit(Instr{Code: bpfRET, K: retAllow})                     // 白名单放行
	if hardenSync {
		p.syncOKAt = p.emit(Instr{Code: bpfRET, K: retErrnoZero}) // 假装成功（errno 0）
	}
	p.patch()
	return pack(p.ins), nil
}

func pack(ins []Instr) []byte {
	b := make([]byte, 0, len(ins)*8)
	for _, i := range ins {
		b = append(b, i.bytes()...)
	}
	return b
}

// Memfd 把 BPF 程序写入 memfd，返回可供子进程继承的 *os.File。
func Memfd(prog []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate("cwrap-seccomp", 0)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	f := os.NewFile(uintptr(fd), "cwrap-seccomp")
	if _, err := f.Write(prog); err != nil {
		f.Close()
		return nil, err
	}
	// 关键：bwrap 用 read() 从当前偏移读程序，写入后偏移停在 EOF，
	// 不回卷会交给 bwrap 一个空程序 → prctl EINVAL。
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
