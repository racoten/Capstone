#include "windows.h"

FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName);
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2);
HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName);
VOID self_load_shellcode(const wchar_t* hostname, const wchar_t* bin);