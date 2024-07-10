It's possible to have a PE without imports by using GetProcAddress and GetModuleHandle custom implementations, and casting them to a function pointer

First define the function you want to create
```cpp
typedef BOOL (WINAPI * CreateProcessA_t)(
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);
  
typedef DWORD (WINAPI * WaitForSingleObject_t)(
  HANDLE hHandle,
  DWORD  dwMilliseconds
);
  
typedef BOOL (WINAPI * CloseHandle_t)(
  HANDLE hObject
);
```

Then cast them as function pointers
```cpp
CreateProcessA_t pCreateProcessA = (CreateProcessA_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "CreateProcessA");
WaitForSingleObject_t pWaitForSingleObject = (WaitForSingleObject_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "WaitForSingleObject");
CloseHandle_t pCloseHandle = (CloseHandle_t) hlpGetProcAddress(hlpGetModuleHandle(L"KERNEL32.DLL"), "CloseHandle");
```

Note to add this at the top
```cpp
#pragma comment(linker, "/entry:WinMain")
```