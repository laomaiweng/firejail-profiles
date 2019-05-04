# Firejail profile for gpg-agent
# Description: GNU privacy guard - cryptographic agent
# Persistent global definitions
include /etc/firejail/globals.local

blacklist /tmp/.X11-unix

noblacklist ${HOME}/.gnupg
whitelist ${HOME}/.gnupg

include /etc/firejail/disable-common.inc
include /etc/firejail/disable-devel.inc
include /etc/firejail/disable-interpreters.inc
include /etc/firejail/disable-passwdmgr.inc
include /etc/firejail/disable-programs.inc

caps.drop all
netfilter
no3d
nodvd
nogroups
nonewprivs
noroot
nosound
notv
novideo
protocol unix,inet,inet6
# Determined with `strace -c`, default 'seccomp' blacklist breaks gpg-agent somehow
seccomp.keep pselect6,wait4,poll,read,write,rt_sigaction,mmap,openat,stat,close,mprotect,fstat,munmap,getpid,getrandom,lstat,brk,access,setresuid,ioctl,getuid,setresgid,accept,readlink,chmod,mlock,bind,pipe,socket,rt_sigprocmask,geteuid,inotify_add_watch,clone,prlimit64,listen,execve,arch_prctl,umask,getdents64,futex,set_robust_list,lseek,getgid,inotify_init,getcwd,dup,fcntl,capset,set_tid_address,utime,alarm,getsockopt,capget,setuid,setgid,madvise,dup2,getpeername,uname,chdir,unlink,getrusage,sysinfo,getegid,getppid,getpgrp,setsid,clock_gettime,name_to_handle_at
shell none

private-cache
# Breaks pinentry-curses spawned by gpg-agent
#private-dev

writable-run-user
