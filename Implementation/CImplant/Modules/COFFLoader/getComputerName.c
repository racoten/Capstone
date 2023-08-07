#include <windows.h>
#include <stdio.h>

typedef int (__cdecl *printf_t)(const char * _Format,...);

int getComputerName() {
    char buffer[256] = "";
    DWORD size = sizeof(buffer);
    printf_t my_printf = (printf_t) GetProcAddress(GetModuleHandle("msvcrt"), "printf");
    if (GetComputerName(buffer, &size))
    {
        my_printf("ComputerName: %s\n", buffer);
    }

    return 0;
}

int go(void) {
    getComputerName();
    return 0;
}
