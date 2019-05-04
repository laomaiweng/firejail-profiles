# Firejail profile for pass
# Description: Stores, retrieves, generates, and synchronizes passwords securely
# Persistent local customizations
include /etc/firejail/pass.local
# Persistent global definitions
include /etc/firejail/globals.local

blacklist /tmp/.X11-unix

noblacklist ${HOME}/.gitconfig
whitelist ${HOME}/.gitconfig
read-only ${HOME}/.gitconfig
whitelist ${HOME}/.gnupg
read-only ${HOME}/.gnupg
read-write ${HOME}/.gnupg/random_seed
whitelist ${HOME}/.ssh
read-only ${HOME}/.ssh
whitelist ${HOME}/.vim
read-only ${HOME}/.vim

noblacklist ${HOME}/.password-store
whitelist ${HOME}/.password-store

include /etc/firejail/disable-devel.inc
include /etc/firejail/disable-interpreters.inc
include /etc/firejail/disable-passwdmgr.inc
include /etc/firejail/disable-programs.inc

caps.drop all
no3d
nodbus
nodvd
nogroups
nonewprivs
noroot
nosound
notv
novideo
protocol unix
seccomp
shell none
net none

private-cache
private-dev

# Required for gpg2 to talk to gpg-agent
writable-run-user

disable-mnt
