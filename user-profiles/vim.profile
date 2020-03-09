# Firejail profile for vim
# Description: Vi IMproved - enhanced vi editor
quiet
# Persistent global definitions
include /etc/firejail/globals.local

# use `safevim` for those
include /etc/firejail/disable-passwdmgr.inc
blacklist ${HOME}/.gnupg
blacklist ${HOME}/.ssh
# but don't fool yourself: vim still has access to a lot of files that can be used for arbitrary command execution (see /etc/firejail/disable-common.inc to get an idea)

caps.drop all
netfilter
nodvd
nogroups
nonewprivs
noroot
notv
novideo
protocol unix,inet,inet6
seccomp

private-dev
# prevents vim from reading files in /tmp, but unbreaks vim plugins that use PID-based temporary directories (e.g., cscope) and end up broken in the PID namespace since they all get the same PID
private-tmp

# keep these readable/modifiable too
keep-var-tmp
keep-dev-shm

# silence Firejailed child processes (esp. required for vim-fugitive to correctly parse git output without Firejail mangling it)
# 'quiet' above should already do this, but force it anyway
env FIREJAIL_QUIET=yes
