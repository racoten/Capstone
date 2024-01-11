Exes and DLLs are both portable executables with the difference being that an EXE can be executed directly, via commands or double clicking, and a DLL has to be loaded before it is executed. Typically using `LoadLibrary` API

A DLL is a collection of different exported functions and code that other programs may use.

![[Pasted image 20231219103543.png]]

In this picture, `explorer.exe` makes use of various DLLs present in the `C:\Windows\System32\` directory.

# System-Wide DLL Base Address

The Windows OS uses a system-wide DLL base address to load some DLLs at the same base address in the virtual address space of all processes on a given machine to optimize memory usage and improve system performance. The following image shows `kernel32.dll` being loaded at the same address (`0x7fff9fad0000`) among multiple running processes.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/dll-new-221233432-97a38697-bd82-45f8-ad5f-90d674de8b17.png)

To create a DLL, we can use Visual Studio:
![[Pasted image 20231219103735.png]]

The following sample will create a DLL with 1 exported function, `HelloWorld()`:
```c
////// sampleDLL.dll //////

#include <Windows.h>

// Exported function
extern __declspec(dllexport) void HelloWorld(){
    MessageBoxA(NULL, "Hello, World!", "DLL Message", MB_ICONINFORMATION);
}

// Entry point for the DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
```

# Dynamic Linking

It is possible to dynamically load a DLL into a process using `LoadLibrary`, `GetModuleHandle` and `GetProcAddress`. This would load the DLL at runtime instead of compile time and using the linker and the import address table.

Dynamic linking has the following advantages over static linking:

- Multiple processes that load the same DLL at the same base address share a single copy of the DLL in physical memory. Doing this saves system memory and reduces swapping.
- When the functions in a DLL change, the applications that use them do not need to be recompiled or relinked as long as the function arguments, calling conventions, and return values do not change. In contrast, statically linked object code requires that the application be relinked when the functions change.
- A DLL can provide after-market support. For example, a display driver DLL can be modified to support a display that was not available when the application was initially shipped.
- Programs written in different programming languages can call the same DLL function as long as the programs follow the same calling convention that the function uses. The calling convention (such as C, Pascal, or standard call) controls the order in which the calling function must push the arguments onto the stack, whether the function or the calling function is responsible for cleaning up the stack, and whether any arguments are passed in registers. For more information, see the documentation included with your compiler.

# Loading the DLL

We can use the following program to first grab the handle of the DLL
```c
#include <windows.h>

int main() {
    // Attempt to get the handle of the DLL that's already in memory
    HMODULE hModule = GetModuleHandleA("sampleDLL.dll");

    if (hModule == NULL) {
        // If the DLL is not loaded in memory, use LoadLibrary to load it
        hModule = LoadLibraryA("sampleDLL.dll");
    }
```

Next, we retrieve the address of the exported function:
```c
#include <windows.h>

int main() {
    // Attempt to get the handle of the DLL
    HMODULE hModule = GetModuleHandleA("sampleDLL.dll");

    if (hModule == NULL) {
        // If the DLL is not loaded in memory, use LoadLibrary to load it
        hModule = LoadLibraryA("sampleDLL.dll");
    }

    PVOID pHelloWorld = GetProcAddress(hModule, "HelloWorld"); /// pHelloWorld stores HelloWorld's function address
}
```

Next, we first create a data type for `HelloWorld`, then we cast the address into said prototype:
```c
#include <windows.h>

// Constructing a new data type that represents HelloWorld's function pointer 
typedef void (WINAPI* HelloWorldFunctionPointer)();

int main() {
    // Attempt to get the handle of the DLL
    HMODULE hModule = GetModuleHandleA("sampleDLL.dll");

    if (hModule == NULL) {
        // If the DLL is not loaded in memory, use LoadLibrary to load it
        hModule = LoadLibraryA("sampleDLL.dll");
    }

    PVOID pHelloWorld = GetProcAddress(hModule, "HelloWorld"); /// pHelloWorld stores HelloWorld's function address

    HelloWorldFunctionPointer HelloWorld = (HelloWorldFunctionPointer)pHelloWorld;
    
    return 0;
}
```

Finally, we call the function to make use of it:
```c
#include <windows.h>

// Constructing a new data type that represents HelloWorld's function pointer 
typedef void (WINAPI* HelloWorldFunctionPointer)();

void call() {
    // Attempt to get the handle of the DLL
    HMODULE hModule = GetModuleHandleA("sampleDLL.dll");

    if (hModule == NULL) {
        // If the DLL is not loaded in memory, use LoadLibrary to load it
        hModule = LoadLibraryA("sampleDLL.dll");
    }

	// pHelloWorld stores HelloWorld's function address
    PVOID pHelloWorld = GetProcAddress(hModule, "HelloWorld"); 


    // Typecasting pHelloWorld to be of type HelloWorldFunctionPointer
    HelloWorldFunctionPointer HelloWorld = (HelloWorldFunctionPointer)pHelloWorld;

	// Invoke HelloWorld
    HelloWorld();
    
}
```

In the following example, we do the same steps but this time we assume `user32.dll` which contains `MessageBoxA` is already loaded into the process:
```c
typedef int (WINAPI* MessageBoxAFunctionPointer)( // Constructing a new data type, that will represent MessageBoxA's function pointer 
  HWND          hWnd,
  LPCSTR        lpText,
  LPCSTR        lpCaption,
  UINT          uType
);

void call(){
    // Retrieving MessageBox's address, and saving it to 'pMessageBoxA' (MessageBoxA's function pointer)
    MessageBoxAFunctionPointer pMessageBoxA = (MessageBoxAFunctionPointer)GetProcAddress(LoadLibraryA("user32.dll"), "MessageBoxA");
    if (pMessageBoxA != NULL){
        // Calling MessageBox via its function pointer if not null    
        pMessageBoxA(NULL, "MessageBox's Text", "MessageBox's Caption", MB_OK); 
    }
}
```

### Rundll32.exe

There are a couple of ways to run exported functions without using a programmatical method. One common technique is to use the [rundll32.exe](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32) binary. `Rundll32.exe` is a built-in Windows binary that is used to run an exported function of a DLL file. To run an exported function use the following command:
```c
rundll32.exe <dllname>, <function exported to run>
```

For example, `User32.dll` exports the function `LockWorkStation` which locks the machine. To run the function, use the following command:
```c
rundll32.exe user32.dll,LockWorkStation
```