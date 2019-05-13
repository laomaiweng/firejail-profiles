# Firejail profile for vimb
# This file is overwritten after every install/update
# Persistent local customizations
include /etc/firejail/vimb.local
# Persistent global definitions
include /etc/firejail/globals.local

noblacklist ${HOME}/.pki

include /etc/firejail/disable-common.inc
include /etc/firejail/disable-devel.inc
include /etc/firejail/disable-interpreters.inc
include /etc/firejail/disable-passwdmgr.inc
include /etc/firejail/disable-programs.inc

whitelist ${DOWNLOADS}
mkdir ${HOME}/.pki
whitelist ${HOME}/.pki
mkdir ${HOME}/.config/vimb
whitelist ${HOME}/.config/vimb
include /etc/firejail/whitelist-common.inc
include /etc/firejail/whitelist-var-common.inc

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
seccomp
shell none

disable-mnt
private-dev
private-tmp

noexec ${HOME}
