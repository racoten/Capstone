
CC_64=x86_64-w64-mingw32-gcc
ASSEMBLER=nasm -f win64
LINKER=x86_64-w64-mingw32-ld

runCode:
	$(ASSEMBLER) adjuststack.asm -o adjuststack.o
	$(CC_64) PIC_httpreverse_shell.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o PIC_httpreverse_shell.o -Wl,-Tlinker.ld,--no-seh
	x86_64-w64-mingw32-ld -s adjuststack.o PIC_httpreverse_shell.o -o PIC_httpreverse_shell.exe