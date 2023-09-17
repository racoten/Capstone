/*

 Red Team Operator course code template
 Find .NET process with RWX memory
 
 author: reenz0h (twitter: @SEKTOR7net)
 credits: Wen Jia Liu
 
*/
#include "Defines.h"

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
    // HANDLE *handles = NULL;
    // int count = 0;
    // char procNameTemp[MAX_PATH];

    // FindDotNet(&handles, &count);

    // for (int i = 0; i < count; ++i) {
    //     HANDLE h = handles[i];
    //     if (h) GetProcessImageFileNameA(h, procNameTemp, MAX_PATH);

    //     printf("[+] DotNet process %s%d) [%s]\n",
    //                     h != 0 ? "found at PID: (" : "NOT FOUND (",
    //                     GetProcessId(h),
    //                     h != 0 ? PathFindFileNameA(procNameTemp) : "<unknown>");

    //     if (!IsModuleLoadedByHandle(h, "System.Runtime.dll")) {
    //         printf("[-] System.Runtime.dll is NOT loaded in the process.\n");
    //         if (LoadRemoteDLL(h, "System.Runtime.dll")) {
    //             printf("[+] Successfully loaded System.Runtime.dll into the process.\n");
    //         } else {
    //             printf("[-] Failed to load System.Runtime.dll into the process.\n");
    //         }
    //     }

    //     // Check again if System.Runtime.dll is loaded.
    //     if (IsModuleLoadedByHandle(h, "System.Runtime.dll")) {
    //         printf("[+] System.Runtime.dll is loaded in the process.\n");
    //     } else {
    //         printf("[-] System.Runtime.dll is NOT loaded in the process.\n");
    //     }

    //     printf("Press Enter to continue...\n");
    //     getchar();  // Wait for a character input

    //     FindRWX(h);
    //     CloseHandle(h);
    // }

    DWORD aProcesses[1024]; 
    DWORD cbNeeded; 
    DWORD cProcesses;
    unsigned int i;

    // Get the list of process identifiers.

    if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
        return 1;

    // Calculate how many process identifiers were returned.

    cProcesses = cbNeeded / sizeof(DWORD);

    // Print the names of the modules for each process.

    for ( i = 0; i < cProcesses; i++ )
    {
        PrintModules( aProcesses[i] );
    }

    return 0;

    //free(handles);  // Free the allocated memory

    return 0;
}
