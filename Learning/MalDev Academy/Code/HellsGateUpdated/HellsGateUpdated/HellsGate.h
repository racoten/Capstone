#pragma once

#ifndef HELLSGATE_H
#define HELLSGATE_H


typedef struct _NT_SYSCALL
{
	DWORD dwSSn;
	DWORD dwSyscallHash;
	PVOID pSyscallAddress;

}NT_SYSCALL, *PNT_SYSCALL;


unsigned int crc32h(char* message);
#define HASH(API) crc32h((char*)API)


// from 'HellsGate.c'
BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys);


// from 'HellsAsm.asm'
extern VOID SetSSn(DWORD wSystemCall);
extern RunSyscall();


#endif // !HELLSGATE_H
