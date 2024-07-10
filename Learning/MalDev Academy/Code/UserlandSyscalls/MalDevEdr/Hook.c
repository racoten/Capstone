#include <Windows.h>
#include <stdio.h>

#include "MinHook.h"
#include "Common.h"


#ifdef _WIN64
#pragma comment(lib, "minhook.x64.lib")
#elif _WIN32
#pragma comment(lib, "minhook.x32.lib")
#endif




fnNtProtectVirtualMemory	g_NtProtectVirtualMemory	= NULL;	// original NtProtectVirtualMemory to call in the hook function
PVOID						pNtProtectVirtualMemory		= NULL;	// address of the NtProtectVirtualMemory function


// what will be executed instead of NtProtectVirtualMemory
NTSTATUS WINAPI Hooked_NtProtectVirtualMemory(
	HANDLE      ProcessHandle,
	PVOID*		BaseAddress,
	PULONG      NumberOfBytesToProtect,
	ULONG       NewAccessProtection,
	PULONG      OldAccessProtection
){


	PRINT("[#] NtProtectVirtualMemory At [ 0x%p ] Of Size [ %d ] \n", (PVOID)*BaseAddress, (unsigned int)*NumberOfBytesToProtect);
	
	// if PAGE_EXECUTE_READWRITE = dump memory + terminate
	if ((NewAccessProtection & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
		PRINT("\t\t\t<<<!>>> [DETECTED] PAGE_EXECUTE_READWRITE [DETECTED] <<<!>>> \n");
		BlockExecution((PBYTE)*BaseAddress, (SIZE_T)*NumberOfBytesToProtect, TRUE);
	}

	// if PAGE_EXECUTE_READWRITE = dump memory + continue
	if ((NewAccessProtection & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ) {
		PRINT("\t\t\t<<<!>>> [DETECTED] PAGE_EXECUTE_READ [DETECTED] <<<!>>> \n");
		BlockExecution((PBYTE)*BaseAddress, (SIZE_T)*NumberOfBytesToProtect, FALSE);
	}

	// return the expected output
	return  g_NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}



// hooking NtProtectVirtualMemory using minhook library
BOOL InstallTheHookviaMinHook() {


	LONG	MinHookErr = MH_OK;

	pNtProtectVirtualMemory = GetProcAddress(GetModuleHandleW(TEXT("NTDLL.DLL")), "NtProtectVirtualMemory");

	if (CreateOutputConsole() == NULL) {
		MessageBoxA(NULL, "Failed To Allocate Console", "ERROR", MB_OK | MB_ICONERROR);
		return FALSE;
	}

	PRINT("\n\t\t\t <><><><><><>[ MALDEV ACAD EDR INJECTED ]<><><><><><> \n\n");


	if ((MinHookErr = MH_Initialize()) != MH_OK) {
		
		("MH_Initialize", MinHookErr);
		return FALSE;
	}

	if (((MinHookErr = MH_CreateHookApi(TEXT("NTDLL.DLL"), "NtProtectVirtualMemory", Hooked_NtProtectVirtualMemory, (LPVOID*)&g_NtProtectVirtualMemory) != MH_OK))) {
		ReportError("MH_CreateHookApi", MinHookErr);
		return FALSE;
	}

	if ((MinHookErr = MH_EnableHook(MH_ALL_HOOKS)) != MH_OK) {
		ReportError("MH_EnableHook", MinHookErr);
		return FALSE;
	}



	return TRUE;
}


// used to dump memory at `pAddress` of size `sSize`
// terminates the process if `Terminate` is true
VOID BlockExecution(PBYTE pAddress, SIZE_T sSize, BOOL Terminate) {

	PRINT("\n\t------------------------------------[ MEMORY DUMP ]------------------------------------\n\n");
	for (int i = 0; i < sSize; i++) {
		if (i % 16 == 0) {
			PRINT("\n\t\t");
		}
		PRINT(" %02X", pAddress[i]);
	}
	PRINT("\n\n\t------------------------------------[ MEMORY DUMP ]------------------------------------\n\n");

	if (Terminate){
		/*
		LONG	MinHookErr = MH_OK;

		if ((MinHookErr = MH_RemoveHook(pNtProtectVirtualMemory)) != MH_OK) {
			ReportError("MH_RemoveHook", MinHookErr);
		}
		*/
		MessageBoxA(NULL, "Terminating The Process ... ", "Maldev Edr", MB_OKCANCEL | MB_ICONERROR);
		ExitProcess(1);
	}
}



// unhooking the installed hook on NtProtectVirtualMemory
VOID ProcessDetachRoutine() {

	LONG	MinHookErr = MH_OK;

	if ((MinHookErr = MH_DisableHook(MH_ALL_HOOKS)) != MH_OK) {
		ReportError("MH_DisableHook", MinHookErr);
	}

	if ((MinHookErr = MH_Uninitialize()) != MH_OK) {
		ReportError("MH_Uninitialize", MinHookErr);
	}

}







