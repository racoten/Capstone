make runCode
clear
for i in $(objdump -d PIC_httpreverse_shell.exe | grep "^ " | cut -f2); do echo -n '\x'$i; done; echo