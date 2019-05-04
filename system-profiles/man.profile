# Firejail profile for man
quiet
# Persistent local customizations
include /etc/firejail/man.local
# Persistent global definitions
include /etc/firejail/globals.local

blacklist /tmp/.X11-unix

include /etc/firejail/disable-common.inc
include /etc/firejail/disable-devel.inc
include /etc/firejail/disable-passwdmgr.inc
include /etc/firejail/disable-programs.inc

whitelist ${HOME}/.local/share/man
whitelist ${HOME}/.manpath

whitelist /var/cache/man/index.db

private-tmp
private-dev

caps.drop all
netfilter
no3d
nodbus
nodvd
nogroups
nonewprivs
noroot
nosound
notv
novideo
net none
seccomp
shell none

disable-mnt
