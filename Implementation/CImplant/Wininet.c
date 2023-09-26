#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#include "GetterFunctions.h"

#pragma comment(lib, "wininet.lib")

int fetchCode(LPCWSTR hostname, LPCWSTR file, LPCWSTR port, unsigned char** buffer, DWORD* size) {
    DWORD bytesRead;
    DWORD totalBytesRead = 0;
    DWORD contentLength = 0;

    wchar_t url[4096];
    wsprintfW(url, L"http://%s:%s/%s", hostname, port, file);
    wprintf(L"URL: %s\n", url);

    HINTERNET hInternet = InternetOpen(L"User Agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("InternetOpen failed. Error: %d\n", GetLastError());
        return -1;
    }

    HINTERNET hConnect = InternetOpenUrl(hInternet, L"http://localhost:8000/TestAssembly.bin", NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hConnect == NULL) {
        printf("InternetOpenUrl failed. Error: %d\n", GetLastError());
        InternetCloseHandle(hInternet);
        return -1;
    }

    if (!InternetQueryDataAvailable(hConnect, &contentLength, 0, 0)) {
        printf("InternetQueryDataAvailable failed. Error: %d\n", GetLastError());
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return -1;
    }

    *buffer = (unsigned char*)malloc(contentLength);
    if (*buffer == NULL) {
        printf("Memory allocation failed.\n");
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return -1;
    }
    *size = contentLength;

    while (InternetReadFile(hConnect, *buffer + totalBytesRead, contentLength - totalBytesRead, &bytesRead) && bytesRead > 0) {
        totalBytesRead += bytesRead;
    }

    if (GetLastError() != ERROR_SUCCESS) {
        printf("InternetReadFile failed. Error: %d\n", GetLastError());
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return (totalBytesRead > 0) ? 0 : -1;
}
