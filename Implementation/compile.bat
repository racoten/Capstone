@ECHO OFF
cl.exe /nologo /Ox /MT /W0 /GS- /DDEBUG /Tc Mokosh.c  /link /OUT:Mokosh.exe /SUBSYSTEM:CONSOLE

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc test.c
move /y test.obj test.o