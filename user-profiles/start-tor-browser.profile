# Firejail profile for start-tor-browser

whitelist ${DOWNLOADS}
whitelist ${HOME}/Tor Browser

# These are custom scripts responsible for firejailing the Tor Browser, they shouldn't be tampered with
read-only ${HOME}/Tor Browser/start-tor-browser
read-only ${HOME}/Tor Browser/start-tor-browser.desktop

include ${CFG}/start-tor-browser.profile
