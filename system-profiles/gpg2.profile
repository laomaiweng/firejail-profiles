# Firejail profile for gpg2
# Description: GNU Privacy Guard -- minimalist public key operations

quiet

# Required to communicate with gpg-agent
writable-run-user

# Redirect
include /etc/firejail/gpg.profile
