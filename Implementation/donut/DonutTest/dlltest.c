#define WIN32_LEAN_AND_MEAN
#define UNICODE

#include <windows.h>
#include "donut.h"

#pragma comment(lib, "user32.lib")

__declspec(dllexport)
VOID APIENTRY DonutApiVoid(VOID) {
    MessageBoxA(NULL, "Hello, World!", "Donut Test for VOID API", MB_OK);
}

__declspec(dllexport)
VOID APIENTRY DonutApiW(PWCHAR argv) {
    MessageBoxW(NULL, argv, L"Donut Test for UNICODE strings", MB_OK);
}

__declspec(dllexport)
VOID APIENTRY DonutApiA(PCHAR argv) {
    MessageBoxA(NULL, argv, "Donut Test for ANSI strings", MB_OK);
}

__declspec(dllexport)
BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
      break;
  }
  return TRUE;
}
