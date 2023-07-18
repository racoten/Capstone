#include <windows.h>
#include <stdio.h>

typedef void (*executeLSFunc)(); // Define the function type

int main() {
    HMODULE hMod = LoadLibrary("F:\\capstone-adversary-emulation-tool\\Research\\MalDev Academy\\ReflectiveDLLLoader\\x64\\Release\\executer.dll");
    if (hMod == NULL) {
        printf("Failed to load DLL\n");
        DWORD errorMessageID = GetLastError();
        printf("Error code: %lu\n", errorMessageID);
        return 1;
    }

    executeLSFunc executeLS = (executeLSFunc)GetProcAddress(hMod, "executeLS");
    if (executeLS == NULL) {
        printf("Failed to get function\n");
        FreeLibrary(hMod);
        return 1;
    }

    executeLS(); // Call the function

    FreeLibrary(hMod); // Don't forget to free the library when you're done with it

    return 0;
}
