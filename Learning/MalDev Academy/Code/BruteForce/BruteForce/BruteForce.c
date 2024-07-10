// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>
#include <time.h>


#define KEYSIZE		16


// used to print buffer as a array of hex
VOID PrintHex(IN PBYTE pBuf, IN SIZE_T sSize) {
	for (int i = 0; i < sSize; i++){
		printf("0x%0.2X ", pBuf[i]);
	}
	printf("\n\n");
}


/*	
	- HintByte : is the same hint byte that was used in the key generating function
	- pProtectedKey : the encrypted key
	- sKey : the key size
	- ppRealKey : pointer to a PBYTE buffer that will recieve the decrypted key
*/
BYTE BruteForceDecryption(IN BYTE HintByte, IN PBYTE pProtectedKey, IN SIZE_T sKey, OUT PBYTE* ppRealKey) {
	
	BYTE			b			= 0;
	PBYTE			pRealKey	= (PBYTE)malloc(sKey);

	if (!pRealKey)
		return NULL;

	while (1){

		// using the hint byte, if this is equal, then we found the 'b' value needed to decrypt the key 
		if (((pProtectedKey[0] ^ b) - 0) == HintByte)
			break;
		// else, increment 'b' and try again
		else
			b++; 
	}

	printf("[+] FOUND\n[+] Calculated Key Byte : 0x%0.2X \n", b);

	for (int i = 0; i < sKey; i++){
		pRealKey[i] = (BYTE)((pProtectedKey[i] ^ b) - i);
	}


	*ppRealKey = pRealKey;

	return b;
}


/*
	- HintByte: is the hint byte that will be saved as the key's first byte
	- sKey: the size of the key to generate
	- ppProtectedKey: pointer to a PBYTE buffer that will recieve the encrypted key
*/
VOID GenerateProtectedKey(IN BYTE HintByte, IN SIZE_T sKey, OUT PBYTE* ppProtectedKey) {
	
	// genereting a seed
	srand(time(NULL));

	// 'b' is used as the key of the key encryption algorithm
	BYTE				b				= rand() % 0xFF;
	// 'pKey' is where the original key will be generated to
	PBYTE				pKey			= (PBYTE)malloc(sKey);
	// 'pProtectedKey' is the encrypted version of 'pKey' using 'b'
	PBYTE				pProtectedKey	= (PBYTE)malloc(sKey);

	if (!pKey || !pProtectedKey)
		return;
	
	// genereting another seed
	srand(time(NULL) * 2);

	// the key starts with the hint byte
	pKey[0] = HintByte;
	// generating the rest of the key
	for (int i = 1; i < sKey; i++){
		pKey[i] = (BYTE)rand() % 0xFF;
	}


	printf("[+] Generated Key Byte : 0x%0.2X \n\n", b);
	printf("[+] Original Key : ");
	PrintHex(pKey, sKey);

	// encrypting the key using a xor encryption algorithm
	// using 'b' as the key
	for (int i = 0; i < sKey; i++){
		pProtectedKey[i] = (BYTE)((pKey[i] + i) ^ b);
	}

	// saving the encrypted key by pointer 
	*ppProtectedKey = pProtectedKey;

	// freeing the raw key buffer
	free(pKey);
}



int main() {


	PBYTE pProtectedKey		= NULL;
	PBYTE pRealKey			= NULL;
	
	// 0xBA is the hint byte
	GenerateProtectedKey(0xBA, KEYSIZE, &pProtectedKey);

	// printing the encrypted key
	printf("[+] Protected Key : ");
	PrintHex(pProtectedKey, KEYSIZE);

	printf("\n\n\t\t\t-------------------------------------------------\n\n");

	// attempting to brute force it, using the same hint byte 
	printf("[i] Brute Forcing The Seed ... ");
	if (!BruteForceDecryption(0xBA, pProtectedKey, KEYSIZE, &pRealKey)) {
		printf("[!] FAILED \n");
		return -1;
	}

	// printing the decrypted key - should be the same as the one printed by the 'GenerateProtectedKey' function
	printf("[+] Original Key : ");
	PrintHex(pRealKey, KEYSIZE);

	// freeing the remaining allocated buffer
	free(pProtectedKey);
	free(pRealKey);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}














