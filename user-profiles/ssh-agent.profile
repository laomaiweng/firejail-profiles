# Firejail profile for ssh-agent
quiet
# Persistent local customizations
include /etc/firejail/ssh-agent.local
# Persistent global definitions
include /etc/firejail/globals.local

noblacklist /etc/ssh
noblacklist /tmp/ssh-*
noblacklist ${HOME}/.ssh

blacklist /tmp/.X11-unix

include /etc/firejail/disable-common.inc
include /etc/firejail/disable-passwdmgr.inc
include /etc/firejail/disable-programs.inc

include /etc/firejail/whitelist-usr-share-common.inc

caps.drop all
netfilter
no3d
nodbus
nodvd
nonewprivs
noroot
notv
novideo
protocol unix
net none
seccomp
shell none
tracelog

writable-run-user
