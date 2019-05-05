" Vim syntax file
" Language: Firejail security sandbox profile
" Maintainer: Quentin Minster
" URL: https://github.com/laomaiweng/firejail-profiles

if exists("b:current_syntax")
  finish
endif


syn iskeyword @,48-57,_,.,-


syn keyword fjTodo TODO FIXME XXX NOTE contained
syn match fjComment "#.*$" contains=fjTodo

"TODO: highlight "dangerous" capabilities differently, as is done in apparmor.vim?
syn keyword fjCapability audit_control audit_read audit_write block_suspend chown dac_override dac_read_search fowner fsetid ipc_lock ipc_owner kill lease linux_immutable mac_admin mac_override mknod net_admin net_bind_service net_broadcast net_raw setgid setfcap setpcap setuid sys_admin sys_boot sys_chroot sys_module sys_nice sys_pacct sys_ptrace sys_rawio sys_resource sys_time sys_tty_config syslog wake_alarm nextgroup=fjCapabilityList contained
syn match fjCapabilityList /,/ nextgroup=fjCapability contained
syn keyword fjCapAll all contained

syn keyword fjProtocol unix inet inet6 netlink packet nextgroup=fjProtocolList contained
syn match fjProtocolList /,/ nextgroup=fjProtocol contained

"TODO: handle 'syscall:errno' syntax
" Syscalls grabbed from: https://github.com/netblue30/firejail/blob/master/src/include/syscall.h (commit 3d84845f859cd3d200eb92a1308dfda7e1374fec)
" Generate list with: rg -o '"([^"]+)' -r '$1' firejail/src/include/syscall.h | sort -u | tr $'\n' ' '
syn keyword fjSyscall _llseek _newselect _sysctl accept accept4 access acct add_key adjtimex afs_syscall alarm arch_prctl bdflush bind bpf break brk capget capset chdir chmod chown chown32 chroot clock_adjtime clock_getres clock_gettime clock_nanosleep clock_settime clone close connect copy_file_range creat create_module delete_module dup dup2 dup3 epoll_create epoll_create1 epoll_ctl epoll_ctl_old epoll_pwait epoll_wait epoll_wait_old eventfd eventfd2 execve execveat exit exit_group faccessat fadvise64 fadvise64_64 fallocate fanotify_init fanotify_mark fchdir fchmod fchmodat fchown fchown32 fchownat fcntl fcntl64 fdatasync fgetxattr finit_module flistxattr flock fork fremovexattr fsetxattr fstat fstat64 fstatat64 fstatfs fstatfs64 fsync ftime ftruncate ftruncate64 futex futimesat get_kernel_syms get_mempolicy get_robust_list get_thread_area getcpu getcwd getdents getdents64 getegid getegid32 geteuid geteuid32 getgid getgid32 getgroups getgroups32 getitimer getpeername getpgid getpgrp getpid getpmsg getppid getpriority getrandom getresgid getresgid32 getresuid getresuid32 getrlimit getrusage getsid getsockname getsockopt gettid gettimeofday getuid getuid32 getxattr gtty idle init_module inotify_add_watch inotify_init inotify_init1 inotify_rm_watch io_cancel io_destroy io_getevents io_setup io_submit ioctl ioperm iopl ioprio_get ioprio_set ipc kcmp kexec_file_load kexec_load keyctl kill lchown lchown32 lgetxattr link linkat listen listxattr llistxattr lock lookup_dcookie lremovexattr lseek lsetxattr lstat lstat64 madvise mbind membarrier memfd_create migrate_pages mincore mkdir mkdirat mknod mknodat mlock mlock2 mlockall mmap mmap2 modify_ldt mount move_pages mprotect mpx mq_getsetattr mq_notify mq_open mq_timedreceive mq_timedsend mq_unlink mremap msgctl msgget msgrcv msgsnd msync munlock munlockall munmap name_to_handle_at nanosleep newfstatat nfsservctl nice oldfstat oldlstat oldolduname oldstat olduname open open_by_handle_at openat pause perf_event_open personality pipe pipe2 pivot_root pkey_alloc pkey_free pkey_mprotect poll ppoll prctl pread64 preadv preadv2 prlimit64 process_vm_readv process_vm_writev prof profil pselect6 ptrace putpmsg pwrite64 pwritev pwritev2 query_module quotactl read readahead readdir readlink readlinkat readv reboot recvfrom recvmmsg recvmsg remap_file_pages removexattr rename renameat renameat2 request_key restart_syscall rmdir rt_sigaction rt_sigpending rt_sigprocmask rt_sigqueueinfo rt_sigreturn rt_sigsuspend rt_sigtimedwait rt_tgsigqueueinfo sched_get_priority_max sched_get_priority_min sched_getaffinity sched_getattr sched_getparam sched_getscheduler sched_rr_get_interval sched_setaffinity sched_setattr sched_setparam sched_setscheduler sched_yield seccomp security select semctl semget semop semtimedop sendfile sendfile64 sendmmsg sendmsg sendto set_mempolicy set_robust_list set_thread_area set_tid_address setdomainname setfsgid setfsgid32 setfsuid setfsuid32 setgid setgid32 setgroups setgroups32 sethostname setitimer setns setpgid setpriority setregid setregid32 setresgid setresgid32 setresuid setresuid32 setreuid setreuid32 setrlimit setsid setsockopt settimeofday setuid setuid32 setxattr sgetmask shmat shmctl shmdt shmget shutdown sigaction sigaltstack signal signalfd signalfd4 sigpending sigprocmask sigreturn sigsuspend socket socketcall socketpair splice ssetmask stat stat64 statfs statfs64 statx stime stty swapoff swapon symlink symlinkat sync sync_file_range syncfs sysfs sysinfo syslog tee tgkill time timer_create timer_delete timer_getoverrun timer_gettime timer_settime timerfd_create timerfd_gettime timerfd_settime times tkill truncate truncate64 tuxcall ugetrlimit ulimit umask umount umount2 uname unlink unlinkat unshare uselib userfaultfd ustat utime utimensat utimes vfork vhangup vm86 vm86old vmsplice vserver wait4 waitid waitpid write writev nextgroup=fjSyscallList contained
" Syscall groups grabbed from: https://github.com/netblue30/firejail/blob/master/src/fseccomp/syscall.c (commit 3d84845f859cd3d200eb92a1308dfda7e1374fec)
" Generate list with: rg -o '"@([^",]+)' -r '$1' src/fseccomp/syscall.c | sort -u | tr $'\n' '|'
syn match fjSyscall /\v\@(clock|cpu-emulation|debug|default|default-keep|default-nodebuggers|module|obsolete|privileged|raw-io|reboot|resources|swap)>/ nextgroup=fjSyscallList contained
syn match fjSyscallList /,/ nextgroup=fjSyscall contained

syn keyword fjX11Sandbox none xephyr xorg xpra xvfb contained

syn match fjEnvVar "[^ =]*=" contained

syn keyword fjShell none contained

syn match fjVar /\v\$\{(CFG|DOCUMENTS|DOWNLOADS|HOME|MUSIC|PATH|PICTURES|VIDEOS)}/

" Commands grabbed from `man firejail-profile`
" With the addition of 'netfilter6' from https://github.com/netblue30/firejail/blob/master/src/firejail/profile.c
syn match fjCommand /\v(include|noblacklist|nowhitelist|blacklist(-nolog)?|bind|mkdir|mkfile|noexec|overlay-named|private(-home|-bin|-etc|-lib|-opt|-srv)?|read-only|read-write|tmpfs|whitelist|xephyr-screen|rlimit-as|rlimit-cpu|rlimit-fsize|rlimit-nproc|rlimit-nofile|rlimit-sigpending|cpu|nice|cgroup|timeout|name|defaultgw|dns|hostname|hosts-file|ip(6|range)?|mac|mtu|netfilter6?|net(mask)?|veth-name|join-or-start)>/ contained
syn match fjCommand /\v(quiet|disable-mnt|keep-var-tmp|overlay(-tmpfs)?|private(-cache|-dev|-tmp)?|keep-dev-shm|tracelog|writable-etc|writable-run-user|writable-var(-log)?|apparmor|caps|seccomp(\.block-secondary)?|memory-deny-write-execute|nonewprivs|noroot|x11|allusers|nodvd|nogroups|ipc-namespace|nodbus|nosound|noautopulse|notv|nou2f|novideo|no3d|machine-id|netfilter)$/ contained
syn match fjCommand /ignore\>/ nextgroup=fjCommand skipwhite contained
syn match fjCommand /caps\.drop\>/ nextgroup=fjCapability,fjCapAll skipwhite contained
syn match fjCommand /caps\.keep\>/ nextgroup=fjCapability skipwhite contained
syn match fjCommand /protocol\>/ nextgroup=fjProtocol skipwhite contained
syn match fjCommand /\vseccomp\.(drop|keep)>/ nextgroup=fjSyscall skipwhite contained
syn match fjCommand /x11\>/ nextgroup=fjX11Sandbox skipwhite contained
syn match fjCommand /env\>/ nextgroup=fjEnvVar skipwhite contained
syn match fjCommand /shell\>/ nextgroup=fjShell skipwhite contained

" Makes sure fjCommand is only matched at the beginning of a line (or following an 'ignore' command)
syn match fjStatement /^/ nextgroup=fjCommand,fjComment

hi def link fjTodo Todo
hi def link fjComment Comment
hi def link fjCommand Statement
hi def link fjVar Identifier
hi def link fjCapability Type
hi def link fjCapAll Type
hi def link fjProtocol Type
hi def link fjSyscall Type
hi def link fjX11Sandbox Type
hi def link fjEnvVar Type
hi def link fjShell Type
hi def link fjMachineId Type


let b:current_syntax = "firejail"
