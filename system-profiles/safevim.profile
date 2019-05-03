# Firejail profile for safevim
# Description: safevim -- wrapper for vim --noplugin
# This file is overwritten after every install/update
# Persistent local customizations
include /etc/firejail/safevim.local
# Persistent global definitions
include /etc/firejail/globals.local

# no blacklist
# the following line doesn't work :(
noblacklist ${HOME}/.config/firejail

caps.drop all
netfilter
nodvd
nogroups
nonewprivs
noroot
notv
novideo
net none
seccomp
shell none

# sh is needed for safevim to exec into vim :(
private-bin safevim,vim,sh
private-dev
