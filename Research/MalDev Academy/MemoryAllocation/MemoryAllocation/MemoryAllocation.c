#include <Windows.h>
#include <stdio.h>

int main() {
	PVOID pAddress = HeapAlloc(GetProcessHeap(), 0, 100);

	printf("[+] Base Address of Allocated Memory: 0x%p \n", pAddress);

	printf("[#] Press <Enter> to Quit...");
	getchar();

	return 0;
}