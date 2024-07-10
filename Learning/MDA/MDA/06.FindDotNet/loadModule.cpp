#include "Defines.h"

BOOL LoadRemoteDLL(HANDLE hProcess, const char *dllPath) {
    DWORD lastError;

    LPVOID remoteString = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (remoteString == NULL) {
        lastError = GetLastError();
        printf("VirtualAllocEx failed. Error: %lu\n", lastError);
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, remoteString, dllPath, strlen(dllPath) + 1, NULL)) {
        lastError = GetLastError();
        printf("WriteProcessMemory failed. Error: %lu\n", lastError);
        VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
        return FALSE;
    }

    HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
    FARPROC hLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (hLoadLibrary == NULL) {
        lastError = GetLastError();
        printf("GetProcAddress failed. Error: %lu\n", lastError);
        VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLibrary, remoteString, 0, NULL);
    if (hThread == NULL) {
        lastError = GetLastError();
        printf("CreateRemoteThread failed. Error: %lu\n", lastError);
        VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    if (exitCode == 0) {
        printf("The remote thread failed to load the DLL.\n");
    }

    VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
    CloseHandle(hThread);

    return exitCode != 0;
}