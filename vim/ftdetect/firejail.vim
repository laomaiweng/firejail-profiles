autocmd BufNewFile,BufRead /etc/firejail/*.profile      set filetype=firejail
autocmd BufNewFile,BufRead /etc/firejail/*.local        set filetype=firejail
autocmd BufNewFile,BufRead /etc/firejail/*.inc          set filetype=firejail
autocmd BufNewFile,BufRead ~/.config/firejail/*.profile set filetype=firejail
autocmd BufNewFile,BufRead ~/.config/firejail/*.local   set filetype=firejail
autocmd BufNewFile,BufRead ~/.config/firejail/*.inc     set filetype=firejail
autocmd BufNewFile,BufRead *.profile
    \ if (getline(1) =~? "^# Firejail profile") |
    \     set filetype=firejail |
    \ endif
