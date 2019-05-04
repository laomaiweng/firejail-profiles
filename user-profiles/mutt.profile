# Firejail profile for mutt

whitelist ${HOME}/.mutt
read-only ${HOME}/.mutt
whitelist ${HOME}/.gnupg
read-only ${HOME}/.gnupg
whitelist ${HOME}/.vim
read-only ${HOME}/.vim
whitelist ${HOME}/.vimrc
read-only ${HOME}/.vimrc

whitelist ${DOWNLOADS}
whitelist ${HOME}/.maildir
whitelist ${HOME}/.maildir-sent
whitelist ${HOME}/.viminfo

# Perl is needed for extract_url
noblacklist ${PATH}/perl
noblacklist /usr/lib/perl*

include ${CFG}/mutt.profile
