; compile with
; nasm -f win64 runshellcode.asm -o runshellcode.o
; x86_64-w64-mingw32-ld runshellcode.o -o runshellcode.exe

Global Start

Start:
    incbin "getprivs.bin"
