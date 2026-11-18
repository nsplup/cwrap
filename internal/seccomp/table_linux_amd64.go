//go:build linux && amd64

package seccomp

import "golang.org/x/sys/unix"

func auditArch() (uint32, bool) { return unix.AUDIT_ARCH_X86_64, true }

// num 返回 syscall 名对应的本机（amd64）调用号。
func num(name string) (uint32, bool) {
	var n int32
	var ok bool
	switch name {
	case "exit":
		n, ok = unix.SYS_EXIT, true
	case "exit_group":
		n, ok = unix.SYS_EXIT_GROUP, true
	case "clone":
		n, ok = unix.SYS_CLONE, true
	case "clone3":
		n, ok = unix.SYS_CLONE3, true
	case "execve":
		n, ok = unix.SYS_EXECVE, true
	case "execveat":
		n, ok = unix.SYS_EXECVEAT, true
	case "wait4":
		n, ok = unix.SYS_WAIT4, true
	case "waitid":
		n, ok = unix.SYS_WAITID, true
	case "kill":
		n, ok = unix.SYS_KILL, true
	case "tgkill":
		n, ok = unix.SYS_TGKILL, true
	case "getpid":
		n, ok = unix.SYS_GETPID, true
	case "getppid":
		n, ok = unix.SYS_GETPPID, true
	case "gettid":
		n, ok = unix.SYS_GETTID, true
	case "getuid":
		n, ok = unix.SYS_GETUID, true
	case "geteuid":
		n, ok = unix.SYS_GETEUID, true
	case "getgid":
		n, ok = unix.SYS_GETGID, true
	case "getegid":
		n, ok = unix.SYS_GETEGID, true
	case "getresuid":
		n, ok = unix.SYS_GETRESUID, true
	case "getresgid":
		n, ok = unix.SYS_GETRESGID, true
	case "getgroups":
		n, ok = unix.SYS_GETGROUPS, true
	case "setgroups":
		n, ok = unix.SYS_SETGROUPS, true
	case "setsid":
		n, ok = unix.SYS_SETSID, true
	case "getpgid":
		n, ok = unix.SYS_GETPGID, true
	case "setpgid":
		n, ok = unix.SYS_SETPGID, true
	case "getpgrp":
		n, ok = unix.SYS_GETPGRP, true
	case "getsid":
		n, ok = unix.SYS_GETSID, true
	case "set_tid_address":
		n, ok = unix.SYS_SET_TID_ADDRESS, true
	case "set_robust_list":
		n, ok = unix.SYS_SET_ROBUST_LIST, true
	case "get_robust_list":
		n, ok = unix.SYS_GET_ROBUST_LIST, true
	case "arch_prctl":
		n, ok = unix.SYS_ARCH_PRCTL, true
	case "prctl":
		n, ok = unix.SYS_PRCTL, true
	case "capget":
		n, ok = unix.SYS_CAPGET, true
	case "capset":
		n, ok = unix.SYS_CAPSET, true
	case "sched_yield":
		n, ok = unix.SYS_SCHED_YIELD, true
	case "sched_getscheduler":
		n, ok = unix.SYS_SCHED_GETSCHEDULER, true
	case "sched_setscheduler":
		n, ok = unix.SYS_SCHED_SETSCHEDULER, true
	case "sched_getparam":
		n, ok = unix.SYS_SCHED_GETPARAM, true
	case "sched_setparam":
		n, ok = unix.SYS_SCHED_SETPARAM, true
	case "sched_getaffinity":
		n, ok = unix.SYS_SCHED_GETAFFINITY, true
	case "sched_setaffinity":
		n, ok = unix.SYS_SCHED_SETAFFINITY, true
	case "sched_getattr":
		n, ok = unix.SYS_SCHED_GETATTR, true
	case "sched_setattr":
		n, ok = unix.SYS_SCHED_SETATTR, true
	case "getpriority":
		n, ok = unix.SYS_GETPRIORITY, true
	case "setpriority":
		n, ok = unix.SYS_SETPRIORITY, true
	case "nice":
		n, ok = 34, true // SYS_NICE
	case "getrusage":
		n, ok = unix.SYS_GETRUSAGE, true
	case "uname":
		n, ok = unix.SYS_UNAME, true
	case "getrandom":
		n, ok = unix.SYS_GETRANDOM, true
	case "getcpu":
		n, ok = unix.SYS_GETCPU, true
	case "sysinfo":
		n, ok = unix.SYS_SYSINFO, true
	case "pidfd_open":
		n, ok = unix.SYS_PIDFD_OPEN, true
	case "pidfd_getfd":
		n, ok = unix.SYS_PIDFD_GETFD, true
	case "close_range":
		n, ok = unix.SYS_CLOSE_RANGE, true
	case "rt_sigaction":
		n, ok = unix.SYS_RT_SIGACTION, true
	case "rt_sigprocmask":
		n, ok = unix.SYS_RT_SIGPROCMASK, true
	case "rt_sigreturn":
		n, ok = unix.SYS_RT_SIGRETURN, true
	case "rt_sigpending":
		n, ok = unix.SYS_RT_SIGPENDING, true
	case "rt_sigsuspend":
		n, ok = unix.SYS_RT_SIGSUSPEND, true
	case "rt_sigtimedwait":
		n, ok = unix.SYS_RT_SIGTIMEDWAIT, true
	case "sigaltstack":
		n, ok = unix.SYS_SIGALTSTACK, true
	case "signal":
		n, ok = 74, true // SYS_SIGNAL
	case "pause":
		n, ok = unix.SYS_PAUSE, true
	case "brk":
		n, ok = unix.SYS_BRK, true
	case "mmap":
		n, ok = unix.SYS_MMAP, true
	case "munmap":
		n, ok = unix.SYS_MUNMAP, true
	case "mremap":
		n, ok = unix.SYS_MREMAP, true
	case "mprotect":
		n, ok = unix.SYS_MPROTECT, true
	case "madvise":
		n, ok = unix.SYS_MADVISE, true
	case "msync":
		n, ok = unix.SYS_MSYNC, true
	case "mincore":
		n, ok = unix.SYS_MINCORE, true
	case "mlock":
		n, ok = unix.SYS_MLOCK, true
	case "munlock":
		n, ok = unix.SYS_MUNLOCK, true
	case "membarrier":
		n, ok = unix.SYS_MEMBARRIER, true
	case "rseq":
		n, ok = unix.SYS_RSEQ, true
	case "pkey_mprotect":
		n, ok = unix.SYS_PKEY_MPROTECT, true
	case "pkey_alloc":
		n, ok = unix.SYS_PKEY_ALLOC, true
	case "pkey_free":
		n, ok = unix.SYS_PKEY_FREE, true
	case "read":
		n, ok = unix.SYS_READ, true
	case "write":
		n, ok = unix.SYS_WRITE, true
	case "open":
		n, ok = unix.SYS_OPEN, true
	case "futex":
		n, ok = unix.SYS_FUTEX, true
	case "openat":
		n, ok = unix.SYS_OPENAT, true
	case "openat2":
		n, ok = unix.SYS_OPENAT2, true
	case "close":
		n, ok = unix.SYS_CLOSE, true
	case "stat":
		n, ok = unix.SYS_STAT, true
	case "fstat":
		n, ok = unix.SYS_FSTAT, true
	case "lstat":
		n, ok = unix.SYS_LSTAT, true
	case "newfstatat":
		n, ok = unix.SYS_NEWFSTATAT, true
	case "statx":
		n, ok = unix.SYS_STATX, true
	case "poll":
		n, ok = unix.SYS_POLL, true
	case "ppoll":
		n, ok = unix.SYS_PPOLL, true
	case "lseek":
		n, ok = unix.SYS_LSEEK, true
	case "pread64":
		n, ok = unix.SYS_PREAD64, true
	case "pwrite64":
		n, ok = unix.SYS_PWRITE64, true
	case "readv":
		n, ok = unix.SYS_READV, true
	case "writev":
		n, ok = unix.SYS_WRITEV, true
	case "access":
		n, ok = unix.SYS_ACCESS, true
	case "faccessat":
		n, ok = unix.SYS_FACCESSAT, true
	case "faccessat2":
		n, ok = unix.SYS_FACCESSAT2, true
	case "dup":
		n, ok = unix.SYS_DUP, true
	case "dup2":
		n, ok = unix.SYS_DUP2, true
	case "dup3":
		n, ok = unix.SYS_DUP3, true
	case "fcntl":
		n, ok = unix.SYS_FCNTL, true
	case "ioctl":
		n, ok = unix.SYS_IOCTL, true
	case "mkdir":
		n, ok = unix.SYS_MKDIR, true
	case "mkdirat":
		n, ok = unix.SYS_MKDIRAT, true
	case "rmdir":
		n, ok = unix.SYS_RMDIR, true
	case "unlink":
		n, ok = unix.SYS_UNLINK, true
	case "unlinkat":
		n, ok = unix.SYS_UNLINKAT, true
	case "rename":
		n, ok = unix.SYS_RENAME, true
	case "renameat":
		n, ok = unix.SYS_RENAMEAT, true
	case "renameat2":
		n, ok = unix.SYS_RENAMEAT2, true
	case "link":
		n, ok = unix.SYS_LINK, true
	case "linkat":
		n, ok = unix.SYS_LINKAT, true
	case "symlink":
		n, ok = unix.SYS_SYMLINK, true
	case "symlinkat":
		n, ok = unix.SYS_SYMLINKAT, true
	case "readlink":
		n, ok = unix.SYS_READLINK, true
	case "readlinkat":
		n, ok = unix.SYS_READLINKAT, true
	case "chmod":
		n, ok = unix.SYS_CHMOD, true
	case "fchmod":
		n, ok = unix.SYS_FCHMOD, true
	case "fchmodat":
		n, ok = unix.SYS_FCHMODAT, true
	case "chown":
		n, ok = unix.SYS_CHOWN, true
	case "fchown":
		n, ok = unix.SYS_FCHOWN, true
	case "lchown":
		n, ok = unix.SYS_LCHOWN, true
	case "fchownat":
		n, ok = unix.SYS_FCHOWNAT, true
	case "umask":
		n, ok = unix.SYS_UMASK, true
	case "getcwd":
		n, ok = unix.SYS_GETCWD, true
	case "chdir":
		n, ok = unix.SYS_CHDIR, true
	case "fchdir":
		n, ok = unix.SYS_FCHDIR, true
	case "truncate":
		n, ok = unix.SYS_TRUNCATE, true
	case "ftruncate":
		n, ok = unix.SYS_FTRUNCATE, true
	case "utime":
		n, ok = unix.SYS_UTIME, true
	case "utimes":
		n, ok = unix.SYS_UTIMES, true
	case "utimensat":
		n, ok = unix.SYS_UTIMENSAT, true
	case "futimesat":
		n, ok = unix.SYS_FUTIMESAT, true
	case "getdents":
		n, ok = unix.SYS_GETDENTS, true
	case "getdents64":
		n, ok = unix.SYS_GETDENTS64, true
	case "fsync":
		n, ok = unix.SYS_FSYNC, true
	case "fdatasync":
		n, ok = unix.SYS_FDATASYNC, true
	case "sync":
		n, ok = unix.SYS_SYNC, true
	case "syncfs":
		n, ok = unix.SYS_SYNCFS, true
	case "statfs":
		n, ok = unix.SYS_STATFS, true
	case "fstatfs":
		n, ok = unix.SYS_FSTATFS, true
	case "fadvise64":
		n, ok = unix.SYS_FADVISE64, true
	case "fallocate":
		n, ok = unix.SYS_FALLOCATE, true
	case "sendfile":
		n, ok = unix.SYS_SENDFILE, true
	case "copy_file_range":
		n, ok = unix.SYS_COPY_FILE_RANGE, true
	case "splice":
		n, ok = unix.SYS_SPLICE, true
	case "vmsplice":
		n, ok = unix.SYS_VMSPLICE, true
	case "tee":
		n, ok = unix.SYS_TEE, true
	case "getxattr":
		n, ok = unix.SYS_GETXATTR, true
	case "lgetxattr":
		n, ok = unix.SYS_LGETXATTR, true
	case "fgetxattr":
		n, ok = unix.SYS_FGETXATTR, true
	case "listxattr":
		n, ok = unix.SYS_LISTXATTR, true
	case "llistxattr":
		n, ok = unix.SYS_LLISTXATTR, true
	case "flistxattr":
		n, ok = unix.SYS_FLISTXATTR, true
	case "setxattr":
		n, ok = unix.SYS_SETXATTR, true
	case "lsetxattr":
		n, ok = unix.SYS_LSETXATTR, true
	case "fsetxattr":
		n, ok = unix.SYS_FSETXATTR, true
	case "removexattr":
		n, ok = unix.SYS_REMOVEXATTR, true
	case "lremovexattr":
		n, ok = unix.SYS_LREMOVEXATTR, true
	case "fremovexattr":
		n, ok = unix.SYS_FREMOVEXATTR, true
	case "memfd_create":
		n, ok = unix.SYS_MEMFD_CREATE, true
	case "pipe":
		n, ok = unix.SYS_PIPE, true
	case "pipe2":
		n, ok = unix.SYS_PIPE2, true
	case "select":
		n, ok = unix.SYS_SELECT, true
	case "pselect6":
		n, ok = unix.SYS_PSELECT6, true
	case "epoll_create":
		n, ok = unix.SYS_EPOLL_CREATE, true
	case "epoll_create1":
		n, ok = unix.SYS_EPOLL_CREATE1, true
	case "epoll_ctl":
		n, ok = unix.SYS_EPOLL_CTL, true
	case "epoll_wait":
		n, ok = unix.SYS_EPOLL_WAIT, true
	case "epoll_pwait":
		n, ok = unix.SYS_EPOLL_PWAIT, true
	case "epoll_pwait2":
		n, ok = unix.SYS_EPOLL_PWAIT2, true
	case "eventfd":
		n, ok = unix.SYS_EVENTFD, true
	case "eventfd2":
		n, ok = unix.SYS_EVENTFD2, true
	case "signalfd":
		n, ok = unix.SYS_SIGNALFD, true
	case "signalfd4":
		n, ok = unix.SYS_SIGNALFD4, true
	case "inotify_init":
		n, ok = unix.SYS_INOTIFY_INIT, true
	case "inotify_init1":
		n, ok = unix.SYS_INOTIFY_INIT1, true
	case "inotify_add_watch":
		n, ok = unix.SYS_INOTIFY_ADD_WATCH, true
	case "inotify_rm_watch":
		n, ok = unix.SYS_INOTIFY_RM_WATCH, true
	case "timerfd_create":
		n, ok = unix.SYS_TIMERFD_CREATE, true
	case "timerfd_settime":
		n, ok = unix.SYS_TIMERFD_SETTIME, true
	case "timerfd_gettime":
		n, ok = unix.SYS_TIMERFD_GETTIME, true
	case "flock":
		n, ok = unix.SYS_FLOCK, true
	case "time":
		n, ok = unix.SYS_TIME, true
	case "gettimeofday":
		n, ok = unix.SYS_GETTIMEOFDAY, true
	case "clock_gettime":
		n, ok = unix.SYS_CLOCK_GETTIME, true
	case "clock_getres":
		n, ok = unix.SYS_CLOCK_GETRES, true
	case "clock_nanosleep":
		n, ok = unix.SYS_CLOCK_NANOSLEEP, true
	case "nanosleep":
		n, ok = unix.SYS_NANOSLEEP, true
	case "alarm":
		n, ok = unix.SYS_ALARM, true
	case "socket":
		n, ok = unix.SYS_SOCKET, true
	case "socketpair":
		n, ok = unix.SYS_SOCKETPAIR, true
	case "connect":
		n, ok = unix.SYS_CONNECT, true
	case "accept":
		n, ok = unix.SYS_ACCEPT, true
	case "accept4":
		n, ok = unix.SYS_ACCEPT4, true
	case "bind":
		n, ok = unix.SYS_BIND, true
	case "listen":
		n, ok = unix.SYS_LISTEN, true
	case "recvfrom":
		n, ok = unix.SYS_RECVFROM, true
	case "recvmsg":
		n, ok = unix.SYS_RECVMSG, true
	case "recvmmsg":
		n, ok = unix.SYS_RECVMMSG, true
	case "sendto":
		n, ok = unix.SYS_SENDTO, true
	case "sendmsg":
		n, ok = unix.SYS_SENDMSG, true
	case "sendmmsg":
		n, ok = unix.SYS_SENDMMSG, true
	case "shutdown":
		n, ok = unix.SYS_SHUTDOWN, true
	case "getsockname":
		n, ok = unix.SYS_GETSOCKNAME, true
	case "getpeername":
		n, ok = unix.SYS_GETPEERNAME, true
	case "setsockopt":
		n, ok = unix.SYS_SETSOCKOPT, true
	case "getsockopt":
		n, ok = unix.SYS_GETSOCKOPT, true
	case "gethostname":
		n, ok = 63, true // SYS_GETHOSTNAME
	case "shmget":
		n, ok = unix.SYS_SHMGET, true
	case "shmat":
		n, ok = unix.SYS_SHMAT, true
	case "shmdt":
		n, ok = unix.SYS_SHMDT, true
	case "shmctl":
		n, ok = unix.SYS_SHMCTL, true
	case "semget":
		n, ok = unix.SYS_SEMGET, true
	case "semop":
		n, ok = unix.SYS_SEMOP, true
	case "semtimedop":
		n, ok = unix.SYS_SEMTIMEDOP, true
	case "semctl":
		n, ok = unix.SYS_SEMCTL, true
	case "msgget":
		n, ok = unix.SYS_MSGGET, true
	case "msgrcv":
		n, ok = unix.SYS_MSGRCV, true
	case "msgsnd":
		n, ok = unix.SYS_MSGSND, true
	case "msgctl":
		n, ok = unix.SYS_MSGCTL, true
	// ===== 黑名单专用（不在白名单中）=====
	case "bpf":
		n, ok = unix.SYS_BPF, true
	case "kexec_load":
		n, ok = unix.SYS_KEXEC_LOAD, true
	case "kexec_file_load":
		n, ok = unix.SYS_KEXEC_FILE_LOAD, true
	case "init_module":
		n, ok = unix.SYS_INIT_MODULE, true
	case "finit_module":
		n, ok = unix.SYS_FINIT_MODULE, true
	case "delete_module":
		n, ok = unix.SYS_DELETE_MODULE, true
	case "swapon":
		n, ok = unix.SYS_SWAPON, true
	case "swapoff":
		n, ok = unix.SYS_SWAPOFF, true
	case "reboot":
		n, ok = unix.SYS_REBOOT, true
	case "acct":
		n, ok = unix.SYS_ACCT, true
	case "ptrace":
		n, ok = unix.SYS_PTRACE, true
	case "process_vm_readv":
		n, ok = unix.SYS_PROCESS_VM_READV, true
	case "process_vm_writev":
		n, ok = unix.SYS_PROCESS_VM_WRITEV, true
	case "keyctl":
		n, ok = unix.SYS_KEYCTL, true
	case "add_key":
		n, ok = unix.SYS_ADD_KEY, true
	case "request_key":
		n, ok = unix.SYS_REQUEST_KEY, true
	case "perf_event_open":
		n, ok = unix.SYS_PERF_EVENT_OPEN, true
	case "setns":
		n, ok = unix.SYS_SETNS, true
	case "fanotify_init":
		n, ok = unix.SYS_FANOTIFY_INIT, true
	case "fanotify_mark":
		n, ok = unix.SYS_FANOTIFY_MARK, true
	case "lookup_dcookie":
		n, ok = unix.SYS_LOOKUP_DCOOKIE, true
	case "open_by_handle_at":
		n, ok = unix.SYS_OPEN_BY_HANDLE_AT, true
	case "name_to_handle_at":
		n, ok = unix.SYS_NAME_TO_HANDLE_AT, true
	case "clock_settime":
		n, ok = unix.SYS_CLOCK_SETTIME, true
	case "settimeofday":
		n, ok = unix.SYS_SETTIMEOFDAY, true
	case "adjtimex":
		n, ok = unix.SYS_ADJTIMEX, true
	case "iopl":
		n, ok = unix.SYS_IOPL, true
	case "ioperm":
		n, ok = unix.SYS_IOPERM, true
	case "create_user_ns":
		n, ok = 322, true // SYS_CREATE_USER_NS
	case "pivot_root":
		n, ok = unix.SYS_PIVOT_ROOT, true
	case "uselib":
		n, ok = unix.SYS_USELIB, true
	case "vfork":
		n, ok = unix.SYS_VFORK, true
	case "fork":
		n, ok = unix.SYS_FORK, true
	}
	if !ok {
		return 0, false
	}
	return uint32(n), true
}
