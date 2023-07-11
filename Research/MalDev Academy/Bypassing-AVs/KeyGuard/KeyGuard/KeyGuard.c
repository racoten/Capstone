// @NUL0x4C | @mrd0x : MalDevAcademy

#include <Windows.h>
#include <stdio.h>
#include <time.h>



// input your key bytes here 
unsigned char Key[] = {
		0x61, 0x1A, 0xA0, 0xAA, 0xA7, 0x92, 0x9F, 0xBA, 0x8F, 0xCE, 0x4C, 0xD8, 0x11, 0xFA, 0xED, 0xB9

};




VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

	printf("unsigned char %s[] = {", Name);

	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X ", Data[i]);
		}
	}

	printf("};\n\n");

}



VOID GenerateProtectedKey(IN PBYTE pKey, IN SIZE_T sKey, OUT PBYTE* ppProtectedKey) {

	srand(time(NULL) / 3);

	BYTE				b = rand() % 0xFF;
	PBYTE				pProtectedKey = (PBYTE)malloc(sKey);

	if (!pKey || !pProtectedKey)
		return;

	srand(time(NULL) * 2);

	for (int i = 1; i < sKey; i++) {
		pKey[i] = (BYTE)rand() % 0xFF;
	}

	PrintHexData("OriginalKey", pKey, sKey);

	for (int i = 0; i < sKey; i++) {
		pProtectedKey[i] = (BYTE)((pKey[i] + i) ^ b);
	}

	*ppProtectedKey = pProtectedKey;

}




VOID PrintFunction() {	
	CHAR* buf =
		"BYTE BruteForceDecryption(IN BYTE HintByte, IN PBYTE pProtectedKey, IN SIZE_T sKey, OUT PBYTE* ppRealKey) {\n\n"
		"\tBYTE		b			= 0;\n"
		"\tINT		i			= 0;\n"
		"\tPBYTE		pRealKey		= (PBYTE)malloc(sKey);\n\n"
		"\tif (!pRealKey)\n"
		"\t\t\b\b\breturn NULL;\n\n"
		"\twhile (1){\n\n"
		"\t\tif (((pProtectedKey[0] ^ b)) == HintByte)\n"
		"\t\t\t\b\b\bbreak;\n"
		"\t\telse\n"
		"\t\t\t\b\b\bb++;\n\n"
		"\t}\n\n"
		"\tfor (int i = 0; i < sKey; i++){\n"
		"\t\tpRealKey[i] = (BYTE)((pProtectedKey[i] ^ b) - i);\n"
		"\t}\n\n"
		"\t*ppRealKey = pRealKey;\n"
		"\treturn b;\n"
		"}\n\n";

	printf("%s", buf);
}




int main() {

	srand(time(NULL));

	PBYTE	pProtectedKey	= NULL;
	BYTE	bHintByte		= (BYTE)(Key[0]);

	printf("/*\n\n");
	printf("[i] Input Key Size : %d \n", sizeof(Key));
	printf("[+] Using \"0x%0.2X\" As A Hint Byte \n\n", bHintByte);

	printf("[+] Use The Following Key For [Encryption] \n");
	GenerateProtectedKey(Key, sizeof(Key), &pProtectedKey);

	printf("[+] Use The Following For [Implementations] \n");
	PrintHexData("ProtectedKey", pProtectedKey, sizeof(Key));

	printf("\n\n\t\t\t-------------------------------------------------\n\n");
	printf("*/\n\n");

	printf("#include <Windows.h>\n\n");
	printf("#define HINT_BYTE 0x%0.2X\n\n", bHintByte);

	PrintHexData("ProtectedKey", pProtectedKey, sizeof(Key));
	PrintFunction();

	printf("// Example calling:\n\n// PBYTE\tpRealKey\t=\tNULL;\n// BruteForceDecryption(HINT_BYTE, ProtectedKey, sizeof(ProtectedKey), &pRealKey); \n\n");

	free(pProtectedKey);

	return 0;
}




