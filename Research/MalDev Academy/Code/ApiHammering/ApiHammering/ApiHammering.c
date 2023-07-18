// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>

// file name to be created
#define TMPFILE	L"MaldevAcad.tmp"

// macro that calculate the 'stress' value 
#define SECTOSTRESS(i)( (int)i * 196 )

// comment to show case api hammering for execution delation 
//\
#define APIHAMMERING_IN_BACKGROUND



#ifndef APIHAMMERING_IN_BACKGROUND
#define APIHAMMERING_AS_DELAY
#endif // !APIHAMMERING_IN_BACKGROUND



BOOL ApiHammering(DWORD dwStress) {

	WCHAR		szPath						[MAX_PATH * 2],
				szTmpPath					[MAX_PATH];

	HANDLE		hRFile						= INVALID_HANDLE_VALUE,
				hWFile						= INVALID_HANDLE_VALUE;
	
	DWORD		dwNumberOfBytesRead			= NULL,
				dwNumberOfBytesWritten		= NULL;
	
	PBYTE		pRandBuffer					= NULL;
	SIZE_T		sBufferSize					= 0xFFFFF;	// 1048575 byte
	
	INT			Random						= 0;

	// getting the tmp folder path
	if (!GetTempPathW(MAX_PATH, szTmpPath)) {
		printf("[!] GetTempPathW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// constructing the file path 
	wsprintfW(szPath, L"%s%s", szTmpPath, TMPFILE);

	for (SIZE_T i = 0; i < dwStress; i++){

		// creating the file in write mode
		if ((hWFile = CreateFileW(szPath, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL)) == INVALID_HANDLE_VALUE) {
			printf("[!] CreateFileW Failed With Error : %d \n", GetLastError());
			return FALSE;
		}

		// allocating a buffer and filling it with a random value
		pRandBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBufferSize);
		Random = rand() % 0xFF;
		memset(pRandBuffer, Random, sBufferSize);

		// writing the random data into the file
		if (!WriteFile(hWFile, pRandBuffer, sBufferSize, &dwNumberOfBytesWritten, NULL) || dwNumberOfBytesWritten != sBufferSize) {
			printf("[!] WriteFile Failed With Error : %d \n", GetLastError());
			printf("[i] Written %d Bytes of %d \n", dwNumberOfBytesWritten, sBufferSize);
			return FALSE;
		}

		// clearing the buffer & closing the handle of the file
		RtlZeroMemory(pRandBuffer, sBufferSize);
		CloseHandle(hWFile);

		// opennig the file in read mode & delete when closed
		if ((hRFile = CreateFileW(szPath, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL)) == INVALID_HANDLE_VALUE) {
			printf("[!] CreateFileW Failed With Error : %d \n", GetLastError());
			return FALSE;
		}

		// reading the random data written before 	
		if (!ReadFile(hRFile, pRandBuffer, sBufferSize, &dwNumberOfBytesRead, NULL) || dwNumberOfBytesRead != sBufferSize) {
			printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
			printf("[i] Read %d Bytes of %d \n", dwNumberOfBytesRead, sBufferSize);
			return FALSE;
		}

		// clearing the buffer & freeing it
		RtlZeroMemory(pRandBuffer, sBufferSize);
		HeapFree(GetProcessHeap(), NULL, pRandBuffer);

		// closing the handle of the file - deleting it
		CloseHandle(hRFile);
	}


	return TRUE;
}


#ifdef APIHAMMERING_AS_DELAY

int main() {

	// GetTickCount64() is used to show how much ApiHammering was able to delay the execution
	// and is not actually needed for the implementation

	DWORD	T0	= NULL,
			T1	= NULL;

	T0 = GetTickCount64();

	if (!ApiHammering(SECTOSTRESS(5))) {
		return -1;
	}

	T1 = GetTickCount64();

	printf(">>> ApiHammering Delayed Execution For : %d \n", (DWORD)(T1 - T0));

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}

#endif // APIHAMMERING_AS_DELAY






#ifdef APIHAMMERING_IN_BACKGROUND

int main() {

	DWORD dwThreadId = NULL;


	if (!CreateThread(NULL, NULL, ApiHammering, -1, NULL, &dwThreadId)) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return -1;
	}

	printf("[+] Thread %d Was Created To Run ApiHammering In The Background\n", dwThreadId);


	/*
	
		injection code can be here

	*/



	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}


#endif // APIHAMMERING_IN_BACKGROUND








