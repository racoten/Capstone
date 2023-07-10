#include <Windows.h>


#ifndef HOOKS_H
#define HOOKS_H



HANDLE CreateOutputConsole();
VOID ReportError(LPCSTR lpFunctionName, DWORD dwError);

// print to screen (act as printf)
#define PRINT( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( CreateOutputConsole(), buf, len, NULL, NULL );                   \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  



typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
    IN		HANDLE      ProcessHandle,
    IN OUT	PVOID*      BaseAddress,
    IN OUT	PULONG      NumberOfBytesToProtect,
    IN		ULONG       NewAccessProtection,
    OUT		PULONG      OldAccessProtection
    );



BOOL InstallTheHookviaMinHook();
VOID ProcessDetachRoutine();
VOID BlockExecution(PBYTE pAddress, SIZE_T sSize, BOOL Terminate);


#endif // !HOOKS_H
