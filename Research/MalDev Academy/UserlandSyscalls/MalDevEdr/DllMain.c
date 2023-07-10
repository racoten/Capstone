#include <Windows.h>
#include <stdio.h>
#include "Common.h"





BOOL APIENTRY DllMain (HMODULE hModule, DWORD dwReason, LPVOID lpReserved){


    HANDLE hThread = NULL;


    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH: {
           hThread = CreateThread(NULL, NULL, &InstallTheHookviaMinHook, NULL, NULL, NULL); //install the hook
           if (hThread)
               CloseHandle(hThread);
           break;
        };

        case DLL_PROCESS_DETACH: {
            ProcessDetachRoutine(); // remove the hooks
            break;
        };
    }

    return TRUE;
}

