# Firejail profile for vim
# Description: Vi IMproved - enhanced vi editor
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
