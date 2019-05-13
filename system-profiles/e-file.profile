# Firejail profile for e-file
# Description: Searchable online file/package database for Gentoo
quiet
# Persistent local customizations
include /etc/firejail/e-file.local
# Persistent global definitions
include /etc/firejail/globals.local

blacklist /tmp/.X11-unix

include /etc/firejail/disable-common.inc
include /etc/firejail/disable-devel.inc
# needs Python for portageq
#include /etc/firejail/disable-interpreters.inc
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
protocol inet,inet6
seccomp
shell none

private
private-dev
private-tmp

noexec ${HOME}
