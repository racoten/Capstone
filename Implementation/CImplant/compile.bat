@ECHO OFF
cl.exe /nologo /Ox /MT /W0 /GS- /DDEBUG /Tc Implant.c  /link /OUT:Implant.exe /SUBSYSTEM:CONSOLE

cl.exe /nologo /c /Od /MT /W0 /GS- /Tc Modules/COFFLoader/getComputerName.c
move /y getComputerName.obj getComputerName.o