#include <windows.h>
#include <stdio.h>

typedef void* (*ExecuteFunc)(unsigned char*, int, const char**, int);

int ExecuteAssembly(unsigned char** asmBytes, char* args) {
    HMODULE hMod = LoadLibrary("..\\..\\..\\ImplantModulesCS\\bin\\Release\\ImplantModulesCS.dll");
    if (hMod == NULL) {
        printf("Could not load the dynamic library\n");
        return EXIT_FAILURE;
    }

    ExecuteFunc execute = (ExecuteFunc)GetProcAddress(hMod, "Execute");
    if (execute == NULL) {
        printf("Could not locate the function\n");
        return EXIT_FAILURE;
    }

    char* result = execute(asmBytes, sizeof(asmBytes), args, sizeof(args));

    printf("Result: %s\n", result);

    FreeLibrary(hMod);
    return 0;
}
