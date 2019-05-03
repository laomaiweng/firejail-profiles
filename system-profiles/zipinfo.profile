# Firejail profile for zipinfo
# Description: List detailed information about a ZIP archive
# Persistent local customizations
include /etc/firejail/zipinfo.local
# Persistent global definitions
# added by included default.profile
#include /etc/firejail/globals.local

private-bin zipinfo

# Redirect
include /etc/firejail/unzip.profile
