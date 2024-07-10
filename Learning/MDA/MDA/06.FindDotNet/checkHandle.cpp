#include "Defines.h"

int PrintModules(DWORD processID) {
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;
    BOOL hasSystemRuntime = FALSE;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (NULL == hProcess) {
        return 1;
    }

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR szModName[MAX_PATH];

            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) {
                TCHAR* fileName = _tcsrchr(szModName, _T('\\'));
                if (fileName != NULL) {
                    fileName++;  // Skip the backslash
                    if (_tcscmp(fileName, _T("System.Runtime.dll")) == 0) {
                        hasSystemRuntime = TRUE;
                        break;
                    }
                }
            }
        }
    }

    CloseHandle(hProcess);

    if (hasSystemRuntime) {
        printf("\nProcess ID: %u\n", processID);
    }

    return 0;
}

BOOL IsModuleLoadedByHandle(HANDLE hProcess, const char* moduleName) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen;

    // Explicitly cast to PROCESSINFOCLASS.
    if (NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)0, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &retLen) != 0) {
        return FALSE;
    }

    PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
        return FALSE;
    }

    PEB_LDR_DATA ldr;
    if (!ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(PEB_LDR_DATA), NULL)) {
        return FALSE;
    }

    LIST_ENTRY* pCurrentEntry = ldr.InMemoryOrderModuleList.Flink;
    while (pCurrentEntry != ldr.InMemoryOrderModuleList.Blink) {
        LDR_DATA_TABLE_ENTRY current;
        if (!ReadProcessMemory(hProcess, CONTAINING_RECORD(pCurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &current, sizeof(LDR_DATA_TABLE_ENTRY), NULL)) {
            return FALSE;
        }

        WCHAR buffer[MAX_PATH];
        if (!ReadProcessMemory(hProcess, current.FullDllName.Buffer, buffer, current.FullDllName.Length, NULL)) {
            return FALSE;
        }
        buffer[current.FullDllName.Length / sizeof(WCHAR)] = 0;

        char currentModuleName[MAX_PATH];
        WideCharToMultiByte(CP_ACP, 0, buffer, -1, currentModuleName, sizeof(currentModuleName), NULL, NULL);

        if (_stricmp(currentModuleName, moduleName) == 0) {
            return TRUE;
        }

        pCurrentEntry = current.InMemoryOrderLinks.Flink;
    }

    return FALSE;
}