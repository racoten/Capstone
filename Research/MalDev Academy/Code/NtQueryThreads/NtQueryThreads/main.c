// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>
#include "Structs.h"

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/thread.htm?ts=0,313

#define STATUS_SUCCESS              0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004


// function pointer
// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
typedef NTSTATUS (WINAPI* fnNtQuerySystemInformation)(
   SYSTEM_INFORMATION_CLASS SystemInformationClass,
   PVOID                    SystemInformation,
   ULONG                    SystemInformationLength,
   PULONG                   ReturnLength
);



BOOL GetRemoteProcessThreads(IN LPCWSTR szProcName, OUT DWORD* pdwPid, OUT DWORD* pdwThread) {

    fnNtQuerySystemInformation		pNtQuerySystemInformation   = NULL;
    ULONG							uReturnLen1                 = NULL,
                                    uReturnLen2                 = NULL;
    PSYSTEM_PROCESS_INFORMATION		SystemProcInfo              = NULL;
    PVOID							pValueToFree                = NULL;
    NTSTATUS						STATUS                      = NULL;

    // Fetching NtQuerySystemInformation's address from ntdll.dll
    pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
    if (pNtQuerySystemInformation == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
        goto _EndOfFunc;
    }

    // First NtQuerySystemInformation call - retrieve the size of the return buffer (uReturnLen1)
    if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1)) != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH) {
        printf("[!] NtQuerySystemInformation [1] Failed With Error : 0x%0.8X \n", STATUS);
        goto _EndOfFunc;
    }

    // Allocating buffer of size "uReturnLen1" 
    SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
    if (SystemProcInfo == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
        goto _EndOfFunc;
    }

    // Setting a fixed variable to be used later to free, because "SystemProcInfo" will be modefied
    pValueToFree = SystemProcInfo;

    // Second NtQuerySystemInformation call - returning the SYSTEM_PROCESS_INFORMATION array (SystemProcInfo)
    if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2)) != STATUS_SUCCESS) {
        printf("[!] NtQuerySystemInformation [2] Failed With Error : 0x%0.8X \n", STATUS);
        goto _EndOfFunc;
    }

    // Enumerating SystemProcInfo, looking for process "szProcName"
    while (TRUE) {

        if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0) {

            // Target process is found, return PID & TID and break
            *pdwPid       = (DWORD)SystemProcInfo->UniqueProcessId;
            *pdwThread    = (DWORD)SystemProcInfo->Threads[0].ClientId.UniqueThread;
            break;
        }

        // If we reached the end of the SYSTEM_PROCESS_INFORMATION structure
        if (!SystemProcInfo->NextEntryOffset)
            break;

        // Calculate the next SYSTEM_PROCESS_INFORMATION element in the array
        SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
    }

    // Free the SYSTEM_PROCESS_INFORMATION structure
_EndOfFunc:
    if (pValueToFree)
        HeapFree(GetProcessHeap(), 0, pValueToFree);
    if (*pdwPid != NULL && *pdwThread != NULL)
        return TRUE;
    else
        return FALSE;
}



VOID ListRemoteProcessThreads(IN LPCWSTR szProcName) {

    fnNtQuerySystemInformation		pNtQuerySystemInformation   = NULL;
    ULONG							uReturnLen1                 = NULL,
                                    uReturnLen2                 = NULL;
    PSYSTEM_PROCESS_INFORMATION		SystemProcInfo              = NULL;
    PSYSTEM_THREAD_INFORMATION      SystemThreadInfo            = NULL;
    PVOID							pValueToFree                = NULL;
    NTSTATUS						STATUS                      = NULL;

    // Fetching NtQuerySystemInformation's address from ntdll.dll
    pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
    if (pNtQuerySystemInformation == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
        goto _EndOfFunc;
    }

    // First NtQuerySystemInformation call - retrieve the size of the return buffer (uReturnLen1)
    if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1)) != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH) {
        printf("[!] NtQuerySystemInformation [1] Failed With Error : 0x%0.8X \n", STATUS);
        goto _EndOfFunc;
    }

    // Allocating buffer of size "uReturnLen1" 
    SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
    if (SystemProcInfo == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
        goto _EndOfFunc;
    }

    // Setting a fixed variable to be used later to free, because "SystemProcInfo" will be modefied
    pValueToFree = SystemProcInfo;

    // Second NtQuerySystemInformation call - returning the SYSTEM_PROCESS_INFORMATION array (SystemProcInfo)
    if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2)) != STATUS_SUCCESS) {
        printf("[!] NtQuerySystemInformation [2] Failed With Error : 0x%0.8X \n", STATUS);
        goto _EndOfFunc;
    }

    // Enumerating SystemProcInfo, looking for process "szProcName"
    while (TRUE) {

        // Searching for thr process name
        if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0) {

            printf("[+] Found target process [ %ws ] - %ld \n", SystemProcInfo->ImageName.Buffer, SystemProcInfo->UniqueProcessId);

            // Fetching the PSYSTEM_THREAD_INFORMATION array
            SystemThreadInfo    = (PSYSTEM_THREAD_INFORMATION)SystemProcInfo->Threads;
            
            // Enumerating "SystemThreadInfo" of size SYSTEM_PROCESS_INFORMATION.NumberOfThreads
            for (DWORD i = 0; i < SystemProcInfo->NumberOfThreads; i++) {
                printf("[+] Thread [ %d ] \n", i);
                printf("\t> Thread Id: %d \n", SystemThreadInfo[i].ClientId.UniqueThread);
                printf("\t> Thread's Start Address: 0x%p\n", SystemThreadInfo[i].StartAddress);
                printf("\t> Thread Priority: %d\n", SystemThreadInfo[i].Priority);
                printf("\t> Thread State: %d\n", SystemThreadInfo[i].ThreadState);
            }

            // Break from while
            break;
        }

        // If we reached the end of the SYSTEM_PROCESS_INFORMATION structure
        if (!SystemProcInfo->NextEntryOffset)
            break;

        // Calculate the next SYSTEM_PROCESS_INFORMATION element in the array
        SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
    }

    // Free the SYSTEM_PROCESS_INFORMATION structure
_EndOfFunc:
    if (pValueToFree)
        HeapFree(GetProcessHeap(), 0, pValueToFree);
    return;
}


#define TARGET_PROCESS L"RuntimeBroker.exe"


int main(){

    DWORD       dwThreadId = NULL, dwProcessId;

    if (!GetRemoteProcessThreads(TARGET_PROCESS, &dwProcessId, &dwThreadId))
        return -1;
    else
        printf("[+] Target Process \"%ws\" Detected With PID [ %d ] & TID [ %d ]\n", TARGET_PROCESS, dwProcessId, dwThreadId);

    //\
    ListRemoteProcessThreads(TARGET_PROCESS);
    
    return 0;
}






