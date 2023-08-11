// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>

#include "Structs.h"


// A helper function that returns a pointer to the PEB structure
PPEB GetPeb () {

#if _WIN64
	return (PPEB)(__readgsqword(0x60));
#elif _WIN32
	return (PPEB)(__readfsdword(0x30));
#endif

	return NULL;
}

//------------------------------------------------------------------------------------------------------------------------------------------------
// Returns the command line 
PWSTR GetCmdLine(OPTIONAL OUT PSIZE_T pSize) {
	
	//  Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;

	// If "pSize" is passed, set it to the length of the returned buffer
	if (pSize)
		*pSize = (SIZE_T)pPeb->ProcessParameters->CommandLine.Length;
	
	// return the command-line string
	return (PWSTR)pPeb->ProcessParameters->CommandLine.Buffer;
}

//------------------------------------------------------------------------------------------------------------------------------------------------
// Returns the current directory of the binary
PWSTR GetCurrentDir(OPTIONAL OUT PSIZE_T pSize) {
	//  Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;

	// If "pSize" is passed, set it to the length of the returned buffer
	if (pSize)
		*pSize = (SIZE_T)pPeb->ProcessParameters->CurrentDirectory.DosPath.Length;

	// return the path of the current directory 
	return (PWSTR)pPeb->ProcessParameters->CurrentDirectory.DosPath.Buffer;
}

//------------------------------------------------------------------------------------------------------------------------------------------------
// Used to print all the environment variables saved in PEB
VOID PrintAllEnvValues() {

	// Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return;
	
	// Get the "Environment" pointer in the "RTL_USER_PROCESS_PARAMETERS" structure 
	PBYTE pTmp = (PBYTE)pPeb->ProcessParameters->Environment;

	while (1)
	{
		// Get the length of "pTmp"
		int j = lstrlenW(pTmp);

		// If zero, break
		if (!j) {
			pTmp = NULL;
			break;
		}

		// Print "pTmp"
		wprintf(L"%s \n\n", pTmp);

		Sleep(10);

		// Add the size (in bytes) of the current environemnt variable to the pointer
		// The "+ sizeof(WCHAR)" is to skip the null terminator of the current environemnt variable
		pTmp = (PBYTE)pTmp + (j * sizeof(WCHAR)) + sizeof(WCHAR);
	}
}

//------------------------------------------------------------------------------------------------------------------------------------------------
// Return the temporary dir path - often "C:\Windows\temp"
PWSTR GetTmpPath() {

	// Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;

	// Get the "Environment" pointer in the "RTL_USER_PROCESS_PARAMETERS" structure 
	PBYTE		pTmp = (PBYTE)pPeb->ProcessParameters->Environment;

	while (1)
	{
		// Get the length of "pTmp"
		int j = lstrlenW(pTmp);

		// If zero, break
		if (!j) {
			pTmp = NULL;
			break;
		}

		// If 'pTmp' starts with the "TEMP" keyword, break
		if (*(ULONG_PTR*)pTmp == *(ULONG_PTR*)L"TEMP")
			break;

		// Else, move to to the next element
		pTmp = (PBYTE)pTmp + (j * sizeof(WCHAR)) + sizeof(WCHAR);
	}


	if (pTmp) {
		// The length of "pTmp" in bytes
		int j = lstrlenW(pTmp) * sizeof(WCHAR);

		for (int i = 0; i <= j; i++) {
			if ((WCHAR)pTmp[i] == (WCHAR)L'=')
				return (PWSTR)&pTmp[i + sizeof(WCHAR)]; // skipping the equal sign
		}
	}
	
	
	return NULL;
}

//------------------------------------------------------------------------------------------------------------------------------------------------
// Return the AppData dir path - often "C:\Users\<username>\AppData"
PWSTR GetAppDataPath() {

	// Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;

	// Get the "Environment" pointer in the "RTL_USER_PROCESS_PARAMETERS" structure 
	PBYTE		pTmp = (PBYTE)pPeb->ProcessParameters->Environment;

	while (1)
	{
		// Get the length of "pTmp"
		int j = lstrlenW(pTmp);

		// If zero, break
		if (!j) {
			pTmp = NULL;
			break;
		}

		// If 'pTmp' starts with the "APPDATA" keyword, break
		if (*(ULONG_PTR*)pTmp == *(ULONG_PTR*)L"APPDATA")
			break;
		
		// Else, move to to the next element
		pTmp = (PBYTE)pTmp + (j * sizeof(WCHAR)) + sizeof(WCHAR);
	}


	if (pTmp) {
		// The length of "pTmp" in bytes
		int j = lstrlenW(pTmp) * sizeof(WCHAR);

		for (int i = 0; i <= j; i++) {
			if ((WCHAR)pTmp[i] == (WCHAR)L'=')
				return (PWSTR)&pTmp[i + sizeof(WCHAR)];  // skipping the equal sign
		}
	}


	return NULL;
}

//------------------------------------------------------------------------------------------------------------------------------------------------
// Return the windir dir path - often "C:\Windows"
PWSTR GetWinDirPath() {

	// Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;

	// Get the "Environment" pointer in the "RTL_USER_PROCESS_PARAMETERS" structure 
	PBYTE		pTmp = (PBYTE)pPeb->ProcessParameters->Environment;

	while (1)
	{
		// Get the length of "pTmp"
		int j = lstrlenW(pTmp);

		// If zero, break
		if (!j) {
			pTmp = NULL;
			break;
		}

		// If 'pTmp' starts with the "windir" keyword, break
		if (*(ULONG_PTR*)pTmp == *(ULONG_PTR*)L"windir")
			break;

		// Else, move to to the next element
		pTmp = (PBYTE)pTmp + (j * sizeof(WCHAR)) + sizeof(WCHAR);
	}


	if (pTmp) {
		// The length of "pTmp" in bytes
		int j = lstrlenW(pTmp) * sizeof(WCHAR);
		
		for (int i = 0; i <= j; i++) {
			if ((WCHAR)pTmp[i] == (WCHAR)L'=')
				return (PWSTR)&pTmp[i + sizeof(WCHAR)]; // skipping the equal sign
		}
	}


	return NULL;
}


//------------------------------------------------------------------------------------------------------------------------------------------------
// Return the number of processors of the system - The value of the NUMBER_OF_PROCESSORS environment variable
DWORD GetNumberOfProcessors() { 

	// Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;

	// Get the "Environment" pointer in the "RTL_USER_PROCESS_PARAMETERS" structure 
	PBYTE		pTmp = (PBYTE)pPeb->ProcessParameters->Environment;

	while (1)
	{
		// Get the length of "pTmp"
		int j = lstrlenW(pTmp);

		// If zero, break
		if (!j) {
			pTmp = NULL;
			break;
		}

		// If 'pTmp' starts with the "NUMBER" keyword, break
		if (*(ULONG_PTR*)pTmp == *(ULONG_PTR*)L"NUMBER") // NUMBER_OF_PROCESSORS
			break;

		pTmp = (PBYTE)pTmp + (j * sizeof(WCHAR)) + sizeof(WCHAR);
	}


	if (pTmp) {
		// The length of "pTmp" in bytes
		int j = lstrlenW(pTmp) * sizeof(WCHAR);

		// skipping the equal sign & converting LPWSTR to DWORD
		for (int i = 0; i <= j; i++) {
			if ((WCHAR)pTmp[i] == (WCHAR)L'=')
				return (DWORD)wcstoul((PWSTR)&pTmp[i + sizeof(WCHAR)], NULL, 10);
		}
	}


	return NULL;
}

//------------------------------------------------------------------------------------------------------------------------------------------------
// Get process ID of the current process
DWORD _GetCurrentProcessId() {

#if _WIN64
	return (DWORD)(__readgsdword(0x40));
#elif _WIN32
	return (DWORD)(__readfsdword(0x20));
#endif

	return NULL;
}

//------------------------------------------------------------------------------------------------------------------------------------------------
// Get process ID of the current thread
DWORD _GetCurrentThreadId() {

#if _WIN64
	return (DWORD)(__readgsdword(0x48));
#elif _WIN32
	return (DWORD)(__readfsdword(0x24));
#endif

	return NULL;
}


//------------------------------------------------------------------------------------------------------------------------------------------------
// The entry point
int main() {
	
	// Uncomment to print all environment variables
	// PrintAllEnvValues();
	
	
	wprintf(L"[+] GetCmdLine : %s \n", GetCmdLine(NULL));
	wprintf(L"[+] GetCurrentDir : %s \n", GetCurrentDir(NULL));

	wprintf(L"[+] GetTmpPath : %s \n", GetTmpPath());
	wprintf(L"[+] GetAppDataPath : %s \n", GetAppDataPath());
	wprintf(L"[+] GetWinDirPath : %s \n", GetWinDirPath());

	wprintf(L"[+] GetNumberOfProcessors : %d \n", GetNumberOfProcessors());

	printf("[+] _GetCurrentProcessId : %d \n", _GetCurrentProcessId());
	printf("[+] _GetCurrentThreadId : %d \n", _GetCurrentThreadId());
	

	printf("[#] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}

