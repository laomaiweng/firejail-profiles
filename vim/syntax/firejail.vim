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
"FIXME: only a single fjCapability is highlighted, nextgroup= doesn't seem like the right thing to use here
syn keyword fjCapability audit_control audit_read audit_write block_suspend chown dac_override dac_read_search fowner fsetid ipc_lock ipc_owner kill lease linux_immutable mac_admin mac_override mknod net_admin net_bind_service net_broadcast net_raw setgid setfcap setpcap setuid sys_admin sys_boot sys_chroot sys_module sys_nice sys_pacct sys_ptrace ssy_rawio sys_resource sys_time sys_tty_config syslog wake_alarm contained nextgroup=fjCapability
syn keyword fjCapAll all contained
"FIXME: only a single fjProtocol is highlighted, nextgroup= doesn't seem like the right thing to use here
syn keyword fjProtocol unix inet inet6 netlink packet contained nextgroup=fjProtocol
"FIXME: only a single fjSyscall is highlighted, nextgroup= doesn't seem like the right thing to use here
" Syscalls grabbed from: https://filippo.io/linux-syscall-table/
syn keyword fjSyscall read write open close stat fstat lstat poll lseek mmap mprotect munmap brk rt_sigaction rt_sigprocmask rt_sigreturn ioctl pread64 pwrite64 readv writev access pipe select sched_yield mremap msync mincore madvise shmget shmat shmctl dup dup2 pause nanosleep getitimer alarm setitimer getpid sendfile socket connect accept sendto recvfrom sendmsg recvmsg shutdown bind listen getsockname getpeername socketpair setsockopt getsockopt clone fork vfork execve exit wait4 kill uname semget semop semctl shmdt msgget msgsnd msgrcv msgctl fcntl flock fsync fdatasync truncate ftruncate getdents getcwd chdir fchdir rename mkdir rmdir creat link unlink symlink readlink chmod fchmod chown fchown lchown umask gettimeofday getrlimit getrusage sysinfo times ptrace getuid syslog getgid setuid setgid geteuid getegid setpgid getppid getpgrp setsid setreuid setregid getgroups setgroups setresuid getresuid setresgid getresgid getpgid setfsuid setfsgid getsid capget capset rt_sigpending rt_sigtimedwait rt_sigqueueinfo rt_sigsuspend sigaltstack utime mknod uselib personality ustat statfs fstatfs sysfs getpriority setpriority sched_setparam sched_getparam sched_setscheduler sched_getscheduler sched_get_priority_max sched_get_priority_min sched_rr_get_interval mlock munlock mlockall munlockall vhangup modify_ldt pivot_root _sysctl prctl arch_prctl adjtimex setrlimit chroot sync acct settimeofday mount umount2 swapon swapoff reboot sethostname setdomainname iopl ioperm create_module init_module delete_module get_kernel_syms query_module quotactl nfsservctl getpmsg putpmsg afs_syscall tuxcall security gettid readahead setxattr lsetxattr fsetxattr getxattr lgetxattr fgetxattr listxattr llistxattr flistxattr removexattr lremovexattr fremovexattr tkill time futex sched_setaffinity sched_getaffinity set_thread_area io_setup io_destroy io_getevents io_submit io_cancel get_thread_area lookup_dcookie epoll_create epoll_ctl_old epoll_wait_old remap_file_pages getdents64 set_tid_address restart_syscall semtimedop fadvise64 timer_create timer_settime timer_gettime timer_getoverrun timer_delete clock_settime clock_gettime clock_getres clock_nanosleep exit_group epoll_wait epoll_ctl tgkill utimes vserver mbind set_mempolicy get_mempolicy mq_open mq_unlink mq_timedsend mq_timedreceive mq_notify mq_getsetattr kexec_load waitid add_key request_key keyctl ioprio_set ioprio_get inotify_init inotify_add_watch inotify_rm_watch migrate_pages openat mkdirat mknodat fchownat futimesat newfstatat unlinkat renameat linkat symlinkat readlinkat fchmodat faccessat pselect6 ppoll unshare set_robust_list get_robust_list splice tee sync_file_range vmsplice move_pages utimensat epoll_pwait signalfd timerfd_create eventfd fallocate timerfd_settime timerfd_gettime accept4 signalfd4 eventfd2 epoll_create1 dup3 pipe2 inotify_init1 preadv pwritev rt_tgsigqueueinfo perf_event_open recvmmsg fanotify_init fanotify_mark prlimit64 name_to_handle_at open_by_handle_at clock_adjtime syncfs sendmmsg setns getcpu process_vm_readv process_vm_writev kcmp finit_module contained nextgroup=fjSyscall
" Syscall groups grabbed from: https://github.com/netblue30/firejail/blob/master/src/fseccomp/syscall.c
syn match fjSyscall /\v\@(clock|cpu-emulation|debug|default|default-nodebuggers|default-keep|module|obsolete|privileged|raw-io|reboot|resources|swap)>/ contained nextgroup=fjSyscall
syn keyword fjX11Sandbox none xephyr xorg xpra xvfb contained
syn match fjEnvVar "[^ =]*=" contained
syn keyword fjShell none contained

syn match fjVar /\v\$\{(CFG|DOCUMENTS|DOWNLOADS|HOME|MUSIC|PATH|PICTURES|VIDEOS)}/

" Commands grabbed from `man firejail-profile`
" With the addition of 'netfilter6' from https://github.com/netblue30/firejail/blob/master/src/firejail/profile.c
syn match fjCommand /\v^(include|noblacklist|nowhitelist|blacklist(-nolog)?|bind|mkdir|mkfile|noexec|overlay-named|private(-home|-bin|-etc|-lib|-opt|-srv)?|read-only|read-write|tmpfs|whitelist|xephyr-screen|rlimit-as|rlimit-cpu|rlimit-fsize|rlimit-nproc|rlimit-nofile|rlimit-sigpending|cpu|nice|cgroup|timeout|name|defaultgw|dns|hostname|hosts-file|ip(6|range)?|mac|mtu|netfilter6?|net(mask)?|veth-name|join-or-start)>/
syn match fjCommand /\v^(quiet|disable-mnt|keep-var-tmp|overlay(-tmpfs)?|private(-cache|-dev|-tmp)?|keep-dev-shm|tracelog|writable-etc|writable-run-user|writable-var(-log)?|apparmor|caps|seccomp(\.block-secondary)?|memory-deny-write-execute|nonewprivs|noroot|x11|allusers|nodvd|nogroups|ipc-namespace|nodbus|nosound|noautopulse|notv|nou2f|novideo|no3d|machine-id|netfilter)$/
"FIXME: doesn't highlight the ignored command :( (perhaps because it's not 'contained'?)
syn match fjCommand /^ignore\>/ nextgroup=fjCommand skipwhite
syn match fjCommand /^caps\.drop\>/ nextgroup=fjCapability,fjCapAll skipwhite
syn match fjCommand /^caps\.keep\>/ nextgroup=fjCapability skipwhite
syn match fjCommand /^protocol\>/ nextgroup=fjProtocol skipwhite
syn match fjCommand /\v^seccomp\.(drop|keep)>/ nextgroup=fjSyscall skipwhite
syn match fjCommand /^x11\>/ nextgroup=fjX11Sandbox skipwhite
syn match fjCommand /^env\>/ nextgroup=fjEnvVar skipwhite
syn match fjCommand /^shell\>/ nextgroup=fjShell skipwhite


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
