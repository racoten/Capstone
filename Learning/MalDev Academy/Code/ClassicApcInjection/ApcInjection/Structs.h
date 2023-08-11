#pragma once
#include <Windows.h>


// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory
typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(

	HANDLE							ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR						ZeroBits,
	PSIZE_T							RegionSize,
	ULONG							AllocationType,
	ULONG							Protect
	);


// http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtProtectVirtualMemory.html
typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(

	HANDLE							ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T							NumberOfBytesToProtect,
	ULONG							NewAccessProtection,
	PULONG							OldAccessProtection
	);

// http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Memory%20Management/Virtual%20Memory/NtWriteVirtualMemory.html
typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(

	HANDLE							ProcessHandle,
	PVOID							BaseAddress,
	PVOID							Buffer,
	ULONG							NumberOfBytesToWrite,
	PULONG							NumberOfBytesWritten
	);


typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;


typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	PVOID				ApcContext,
	PIO_STATUS_BLOCK	IoStatusBlock,
	ULONG				Reserved
	);

// http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/APC/NtQueueApcThread.html
typedef NTSTATUS(NTAPI* fnNtQueueApcThread)(

	HANDLE							ThreadHandle,
	PIO_APC_ROUTINE					ApcRoutine,
	PVOID							ApcRoutineContext,
	PIO_STATUS_BLOCK				ApcStatusBlock,
	ULONG							ApcReserved
	);



