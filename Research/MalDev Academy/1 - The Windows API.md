
# Data Types

`DWORD` - 32-bit unsigned int for 32-64 bit systems.
```c
DWORD dwVariable = 42;
```
`size_t` - Represent the size of an Object. 32-bit unsigned int on 32-bit systems, and 64-bit unsigned int on 64-bit systems.
```c
SIZE_T sVariable = sizeof(int);
```
`VOID` - Absence of a data type.
```c
void* pVariable = NULL; // This is the same as PVOID
```
`PVOID` - 32-bit (4-byte) pointer of any data type on 32-bit systems. Similarly 64-bit (8 bytes) on 64-bit systems.
```c
PVOID pVariable = &SomeData;
```
`HANDLE` - Specifies a particular object the OS is managing.
```c
HANDLE hFile = CreateFile(...);
```
`HMODULE` - A handle to a module DLL or EXE. Contains the base address of the module.
```c
HMODULE hModule = GetModuleHandle(...);
```
`LPCSTR/PCSTR` - A pointer to a constant null-terminated string of 8 bit Windows character (ANSI). `L` stands for "long" derived from the 16-bit windows. The `C` stands for constant as in "read-only". (Both are `const char*`)
```c
LPCSTR  lpcString   = "Hello, world!";
PCSTR   pcString    = "Hello, world!";
```
`LPSTR/PSTR` - Same as `LPCSTR/PCSTR` but they can be readable AND writeable. (Both are `char*`)
```c
LPSTR   lpString    = "Hello, world!";
PSTR    pString     = "Hello, world!";
```
`LPCWSTR/PCWSTR` - A pointer to a constant null-terminated string of 16-bit Windows Unicode characters (Unicode). (Both are `const wchar*`)
```c
LPCWSTR     lpwcString  = L"Hello, world!";
PCWSTR      pcwString   = L"Hello, world!";
```
`PWSTR\LPWSTR` - Same as `LPSTR/PSTR` But instead pointing to a readable/writeable 16-bit unicode character.
```c
LPWSTR  lpwString   = L"Hello, world!";
PWSTR   pwString    = L"Hello, world!";
```
`wchat_t` - Same as `wchar`.
```c
wchar_t     wChar           = L'A';
wchar_t*    wcString        = L"Hello, world!";
```
`ULONG_PTR` - Represents an unsigned int that is the same size as a pointer on the specific architecture. Meaning it will be 32-bit size on 32-bit system, and 64-bits on 64-bit systems.
```c
PVOID Pointer = malloc(100);
// Pointer = Pointer + 10; // not allowed
Pointer = (ULONG_PTR)Pointer + 10; // allowed
```

# Data Types Pointers

On Windows, it is allowed for a developer to declare a type directly or a pointer to a data type. This can be noted from the `P` as a prefix to all data types.
- `PHANDLE` is the same as `HANDLE*`.
- `PSIZE_T` is the same as `SIZE_T*`.
- `PDWORD` is the same as `DWORD*`.

# ANSI & Unicode Functions

Most Win32 APIs are either "A" (ANSI) or "W" (Unicode). Example:
```c
CreateFileA();
https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea

CreateFileW();
https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
```

The main difference is that `CreateFileA()` will take ANSI type parameters where applicable, whereas `CreateFileW()` will take Unicode type parameters. For instance, `CreateFileA()` has a parameter `LPCSTR`, on the other hand, `CreateFileW()` has a parameter `LPCWSTR`.

`char str1[] = "maldev";` // 7 bytes ("maldev" + [null byte](https://www.tutorialandexample.com/null-character-in-c)).
`wchar str2[] = L"maldev";` // 14 bytes, each character is 2 bytes (The null byte is also 2 bytes

# In and Out Parameters

Inside the function signature for the parameters, an API may have defined one or multiple variables that can be used as input or output. Example:
```c
BOOL HackTheWorld(OUT int* num){

    // Setting the value of num to 123
    *num = 123;
    
    // Returning a boolean value
    return TRUE;
}

int main(){
    int a = 0;

    // 'HackTheWorld' will return true
    // 'a' will contain the value 123
    HackTheWorld(&a);
}
```

This convention allows the developer how to work with the values passed to each API.

# Using CreateFile API

It's important to always reference the documentation if one is unsure about what the function does or what arguments it requires. Always read the description of the function and assess whether the function accomplishes the desired task. The `CreateFileW` documentation is available [here](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).

The next step would be to view the parameters of the function along with the return data type. The documentation states _If the function succeeds, the return value is an open handle to the specified file, device, named pipe, or mail slot_ therefore `CreateFileW` returns a `HANDLE` data type to the specified item that's created.

Furthermore, notice that the function parameters are all `in` parameters. This means the function does not return any data from the parameters since they are all `in` parameters. Keep in mind that the keywords within the square brackets, such as `in`, `out`, and `optional`, are purely for developers' reference and do not have any actual impact.
```c
HANDLE CreateFileW(
  [in]           LPCWSTR               lpFileName,
  [in]           DWORD                 dwDesiredAccess,
  [in]           DWORD                 dwShareMode,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  [in]           DWORD                 dwCreationDisposition,
  [in]           DWORD                 dwFlagsAndAttributes,
  [in, optional] HANDLE                hTemplateFile
);
```

To use this function, we take into account the parameters needed in order to use it:
```c
// This is needed to store the handle to the file object
// the 'INVALID_HANDLE_VALUE' is just to intialize the variable
HANDLE hFile = INVALID_HANDLE_VALUE; 

// The full path of the file to create.
// Double backslashes are required to escape the single backslash character in C
// Make sure the username (maldevacademy) exists, otherwise modify it
LPCWSTR filePath = L"C:\\Users\\maldevacademy\\Desktop\\maldev.txt";

// Call CreateFileW with the file path
// The additional parameters are directly from the documentation
/*
This line is where the `CreateFileW` function is called with several parameters:

- `filePath`: The path of the file to be created or opened.
- `GENERIC_ALL`: This parameter specifies the desired access to the file. `GENERIC_ALL` means requesting all possible access rights.
- `0`: This is the file sharing mode. `0` means that the file cannot be shared and if opened, other processes cannot read or write to the file.
- `NULL`: This is a pointer to a `SECURITY_ATTRIBUTES` structure. `NULL` indicates that the file handle cannot be inherited by child processes.
- `CREATE_ALWAYS`: This parameter specifies the action to take on files that exist or don't exist. `CREATE_ALWAYS` means to create a new file. If the file exists, it will be overwritten.
- `FILE_ATTRIBUTE_NORMAL`: Indicates that the file should be created with no special attributes.
- `NULL`: This last parameter is for templates. `NULL` means that no template file is used.
*/
hFile = CreateFileW(filePath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

// On failure CreateFileW returns INVALID_HANDLE_VALUE
// GetLastError() is another Windows API that retrieves the error code of the previously executed WinAPI function
if (hFile == INVALID_HANDLE_VALUE){
    printf("[-] CreateFileW Api Function Failed With Error : %d\n", GetLastError());
    return -1;
}
```

# Windows API Debugging Errors

APIs will often return a non-verbose error if such would occur. `CreateFileW` returns an `INVALID_HANDLE_VALUE` error which indicates the file cannot be created. To gain more insight, use the [GetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror) function.

Once the code is retrieved, it needs to be looked up in [Windows's System Error Codes List](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-). Some common error codes are translated below:

- `5` - ERROR_ACCESS_DENIED
- `2` - ERROR_FILE_NOT_FOUND
- `87` - ERROR_INVALID_PARAMETER

# Windows Native API Debugging Errors

Unlike Win32 APIs, Native APIs return the error directly represented as `NTSTATUS`. Native APIs cannot have their error code fetched via `GetLastError`.

`NTSTATUS` is used to represent the status of a system call or function and is defined as a 32-bit unsigned integer value. A successful system call will return the value `STATUS_SUCCESS`, which is `0`. On the other hand, if the call failed it will return a non-zero value, to further investigate the cause of the problem, one must check [Microsoft's documentation on NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55).

Example on how to check for Native API errors:
```c
NTSTATUS STATUS = NativeSyscallExample(...);
if (STATUS != STATUS_SUCCESS){
    // printing the error in unsigned integer hexadecimal format
    printf("[!] NativeSyscallExample Failed With Status : 0x%0.8X \n", STATUS); 
}

// NativeSyscallExample succeeded
```

#### NT_SUCCESS Macro

Another way to check the return value of NTAPIs is through the `NT_SUCCESS` macro shown [here](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values). The macro returns `TRUE` if the function succeeded, and `FALSE` it fails.
```c
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
```

Below, is an example of using this macro
```c
NTSTATUS STATUS = NativeSyscallExample(...);
if (!NT_SUCCESS(STATUS)){
    // printing the error in unsigned integer hexadecimal format
    printf("[!] NativeSyscallExample Failed With Status : 0x%0.8X \n", STATUS); 
}

// NativeSyscallExample succeeded
```