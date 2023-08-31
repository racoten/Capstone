#include "Structs.h"
#include "Windows.h"

BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {

	WCHAR	lStr1[MAX_PATH],
		lStr2[MAX_PATH];

	int		len1 = lstrlenW(Str1),
		len2 = lstrlenW(Str2);

	int		i = 0,
		j = 0;

	// checking - we dont want to overflow our buffers
	if (len1 >= MAX_PATH || len2 >= MAX_PATH)
		return FALSE;

	// converting Str1 to lower case string (lStr1)
	for (i = 0; i < len1; i++) {
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	}
	lStr1[i++] = L'\0'; // null terminating


	// converting Str2 to lower case string (lStr2)
	for (j = 0; j < len2; j++) {
		lStr2[j] = (WCHAR)tolower(Str2[j]);
	}
	lStr2[j++] = L'\0'; // null terminating


	// comparing the lower-case strings
	if (lstrcmpiW(lStr1, lStr2) == 0)
		return TRUE;

	return FALSE;
}



// function that replaces GetModuleHandle
// it uses pointers to enumerate in the dlls  
HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName) {

	// getting peb
#ifdef _WIN64 // if compiling as x64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	// geting Ldr
	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	// getting the first element in the linked list (contains information about the first module)
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		// if not null
		if (pDte->FullDllName.Length != NULL) {

			// check if both equal
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {

#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif // STRUCTS

			}

			// wprintf(L"[i] \"%s\" \n", pDte->FullDllName.Buffer);
		}
		else {
			break;
		}

		// next element in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

	}

	return NULL;
}

FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName) {

	// we do this to avoid casting at each time we use 'hModule'
	PBYTE pBase = (PBYTE)hModule;

	// getting the dos header and doing a signature check
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// getting the nt headers and doing a signature check
	PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// getting the optional header
	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;

	// we can get the optional header like this as well																								
	// PIMAGE_OPTIONAL_HEADER	pImgOptHdr	= (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)pImgNtHdrs + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

	// getting the image export table
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// getting the function's names array pointer
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	// getting the function's addresses array pointer
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	// getting the function's ordinal array pointer
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);


	// looping through all the exported functions
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		// getting the name of the function
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

		// getting the address of the function through its ordinal
		FARPROC pFunctionAddress = (FARPROC)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// searching for the function specified
		if (strcmp(lpApiName, pFunctionName) == 0) {
			// printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
			return pFunctionAddress;
		}

		// printf("[ %0.4d ] NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
	}

	return NULL;
}

// Functions below are provided by the VX-API

PVOID CopyMemoryEx(_Inout_ PVOID Destination, _In_ CONST PVOID Source, _In_ SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

BOOL GetByteArrayFromFileW(_Inout_ PBYTE Buffer, _In_ PWCHAR Path, _In_ ULONGLONG BytesToRead)
{
	HANDLE hHandle = INVALID_HANDLE_VALUE;
	BOOL bFlag = FALSE;

	hHandle = CreateFileW(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hHandle == INVALID_HANDLE_VALUE)
		goto EXIT_ROUTINE;

	if (!ReadFile(hHandle, Buffer, (DWORD)BytesToRead, NULL, NULL))
		goto EXIT_ROUTINE;

	bFlag = TRUE;

EXIT_ROUTINE:

	if (hHandle)
		CloseHandle(hHandle);

	return TRUE;
}

BOOL GetByteArrayFromFileA(_Inout_ PBYTE Buffer, _In_ PCHAR Path, _In_ ULONGLONG BytesToRead)
{
	HANDLE hHandle = INVALID_HANDLE_VALUE;
	BOOL bFlag = FALSE;

	hHandle = CreateFileA(Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hHandle == INVALID_HANDLE_VALUE)
		goto EXIT_ROUTINE;

	if (!ReadFile(hHandle, Buffer, (DWORD)BytesToRead, NULL, NULL))
		goto EXIT_ROUTINE;

	bFlag = TRUE;

EXIT_ROUTINE:

	if (hHandle)
		CloseHandle(hHandle);

	return TRUE;
}

PPEB GetPeb(VOID)
{
#if defined(_WIN64)
	return (PPEB)__readgsqword(0x60);
#elif define(_WIN32)
	return (PPEB)__readfsdword(0x30);
#endif
}

DWORD GetCurrentProcessIdFromOffset(VOID)
{
#if defined(_WIN64)
	return (UINT32)__readgsqword(0x40);
#elif define(_WIN32)
	return (UINT32)__readfsdword(0x20);
#endif
}

HANDLE GetProcessHeapFromTeb(VOID)
{
	return GetPeb()->ProcessHeap;
}
