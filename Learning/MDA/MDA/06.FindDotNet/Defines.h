#include <windows.h>
#include <winternl.h>
#include <tchar.h>
#include <stdio.h>
#include <Psapi.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <metahost.h>
#include <iostream>

#pragma comment(lib, "mscoree.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Shlwapi.lib")

BOOL LoadRemoteDLL(HANDLE hProcess, const char *dllPath);
BOOL IsModuleLoadedByHandle(HANDLE hProcess, const char* moduleName);
int PrintModules( DWORD processID );
HRESULT EnumerateAppDomains(HANDLE processHandle);