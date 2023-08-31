#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")

int fetchCode(const wchar_t* hostname, const wchar_t* file, int port, unsigned char** buffer, DWORD* size) {
    HINTERNET hSession, hConnect, hRequest;
    DWORD dwBytesRead, dwContentSize = 1024, dwDownloaded = 0;

    hSession = InternetOpen("MyApp", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hSession) return 1;

    hConnect = InternetConnect(hSession, hostname, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hSession);
        return 1;
    }

    hRequest = HttpOpenRequest(hConnect, "GET", file, NULL, NULL, NULL, 0, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hSession);
        return 1;
    }

    if (!HttpSendRequest(hRequest, NULL, 0, NULL, 0)) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hSession);
        return 1;
    }

    *buffer = (unsigned char*)malloc(dwContentSize);
    if (!(*buffer)) return 1;

    while (InternetReadFile(hRequest, (*buffer) + dwDownloaded, dwContentSize - dwDownloaded, &dwBytesRead)) {
        if (dwBytesRead == 0) break;

        dwDownloaded += dwBytesRead;

        if (dwDownloaded >= dwContentSize) {
            dwContentSize *= 2;
            unsigned char* newBuffer = (unsigned char*)realloc(*buffer, dwContentSize);
            if (!newBuffer) {
                free(*buffer);
                return 1;
            }
            *buffer = newBuffer;
        }
    }

    *size = dwDownloaded;

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hSession);

    return 0;
}
