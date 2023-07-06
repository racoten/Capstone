#include <Windows.h>
#include <stdio.h>

int main() {
	PVOID pAddress = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 100);

	CHAR* cString = "MalDev Academy Is The Best";

	memcpy(pAddress, cString, strlen(cString));

	printf("[+] Base Address of Allocated Memory: 0x%p \n", pAddress);

	printf("[#] Press <Enter> to Quit...");
	getchar();

	return 0;
}