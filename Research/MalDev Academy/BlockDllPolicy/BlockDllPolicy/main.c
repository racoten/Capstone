// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>

// Comment to create a remote process with block dll policy enabled
//\
#define LOCAL_BLOCKDLLPOLICY


#ifdef LOCAL_BLOCKDLLPOLICY
#define STOP_ARG "MalDevAcad"
#endif // LOCAL_BLOCKDLLPOLICY



// function that creates 'lpProcessPath' process with block dll policy enabled
BOOL CreateProcessWithBlockDllPolicy(IN LPCSTR lpProcessPath, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {


	STARTUPINFOEXA			SiEx			= { 0 };
	PROCESS_INFORMATION		Pi				= { 0 };
	SIZE_T					sAttrSize		= NULL;
	PVOID					pAttrBuf		= NULL;

	if (lpProcessPath == NULL)
		return FALSE;

	// Cleaning the structs by setting the member values to 0
	RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	SiEx.StartupInfo.cb			= sizeof(STARTUPINFOEXA);
	SiEx.StartupInfo.dwFlags	= EXTENDED_STARTUPINFO_PRESENT;

	// Get the size of our PROC_THREAD_ATTRIBUTE_LIST to be allocated
	InitializeProcThreadAttributeList(NULL, 1, NULL, &sAttrSize);
	pAttrBuf = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sAttrSize);

	// Initialise our list 
	if (!InitializeProcThreadAttributeList(pAttrBuf, 1, NULL, &sAttrSize)) {
		printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Enable blocking of non-Microsoft signed DLLs
	DWORD64 dwPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	// Assign our attribute
	if (!UpdateProcThreadAttribute(pAttrBuf, NULL, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwPolicy, sizeof(DWORD64), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	SiEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)pAttrBuf;

	printf("[i] Running : \"%s\" With Block Dll Policy ... ", lpProcessPath);
	if (!CreateProcessA(
		NULL,
		lpProcessPath,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		&SiEx.StartupInfo,
		&Pi)) {
		printf("[!] CreateProcessA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[+] DONE \n");


	*dwProcessId	= Pi.dwProcessId;
	*hProcess		= Pi.hProcess;
	*hThread		= Pi.hThread;

	// Cleaning up
	DeleteProcThreadAttributeList(pAttrBuf);
	HeapFree(GetProcessHeap(), 0, pAttrBuf);

	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;
	else
		return FALSE;
}






int main(int argc, char* argv[]) {

	DWORD	dwProcessId = NULL;
	HANDLE	hProcess	= NULL,
			hThread		= NULL;

#ifdef LOCAL_BLOCKDLLPOLICY

	if (argc == 2 && (strcmp(argv[1], STOP_ARG) == 0)) {
	
	 /*
	
		the real implementation code
	 
	 */
		printf("[+] Process Is Now Protected With The Block Dll Policy \n");
		WaitForSingleObject((HANDLE)-1, INFINITE);
	}
	else {

		printf("[!] Local Process Is Not Protected With The Block Dll Policy \n");

		// getting the local process path + name
		CHAR pcFilename[MAX_PATH * 2];
		if (!GetModuleFileNameA(NULL, &pcFilename, MAX_PATH * 2)) {
			printf("[!] GetModuleFileNameA Failed With Error : %d \n", GetLastError());
			return -1;
		}

		// re-creating local process, so we add the process argument
		// 'pcBuffer' = 'pcFilename' + 'STOP_ARG'

		DWORD dwBufferSize = (DWORD)(lstrlenA(pcFilename) + lstrlenA(STOP_ARG) + 0xFF);
		CHAR* pcBuffer = (CHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);
		if (!pcBuffer)
			return FALSE;

		sprintf_s(pcBuffer, dwBufferSize, "%s %s", pcFilename, STOP_ARG);

		// fork with block dll policy
		if (!CreateProcessWithBlockDllPolicy(pcBuffer, &dwProcessId, &hProcess, &hThread)) {
			return -1;
		}

		HeapFree(GetProcessHeap(), 0, pcBuffer);

		printf("[i] Process Created With Pid %d \n", dwProcessId);

	}

#endif // LOCAL_BLOCKDLLPOLICY


#ifndef LOCAL_BLOCKDLLPOLICY
	// if LOCAL_BLOCKDLLPOLICY is not defined
	if (!CreateProcessWithBlockDllPolicy("C:\\Windows\\System32\\RuntimeBroker.exe", &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}
	printf("[i] Process Created With Pid %d \n", dwProcessId);

#endif // !LOCAL_BLOCKDLLPOLICY

	return 0;

}










