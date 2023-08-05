/*

 Red Team Operator course code template
 COFF module template
 
 author: reenz0h (twitter: @SEKTOR7net)
 credits: COFFLoader (by Kevin Haubris/@kev169)

*/

#include <windows.h>
#include <stdio.h>

// DECLSPEC_IMPORT <return_type> WINAPI <LIB>$<FUNCNAME>(param1, param2, ...);
// ex. DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD th32ProcessID);

// WINBASEAPI <return_type> __cdecl MSVCRT$<FUNCNAME>(param1, param2, ...);
// ex. WINBASEAPI int __cdecl MSVCRT$getchar(void);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);

int getComputerName(){
	char buffer[256] = "";
    DWORD size = sizeof(buffer);
    if (GetComputerName(buffer, &size))
    {
        MSVCRT$printf("ComputerName: %s\n", buffer);
    }

	return 0;
}

int go(void) {

	getComputerName();

	return 0;
}