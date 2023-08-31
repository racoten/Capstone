#include "windows.h"

FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName);
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2);
HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName);
