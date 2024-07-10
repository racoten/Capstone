This section makes use of the [tiny-AES-c](https://github.com/kokke/tiny-AES-c) third-party encryption library that performs AES encryption without the use of WinAPIs. Tiny-AES-C is a small portable library that can perform AES128/192/256 in C.

#### Setting Up Tiny-AES

To begin using Tiny-AES there are two requirements:

1. Include `aes.hpp` (C++) or include `aes.h` (C) in the project.
2. Add the `aes.c` file to the project.

#### Setting The AES256 Flag

By default, the library applies the AES128 algorithm for encryption and decryption. However, one can set the library to use AES256 or AES192 algorithms by enabling one of the [AESXXX flags](https://github.com/kokke/tiny-AES-c/blob/master/aes.h#L27) located in the `aes.h` file and commenting the other flags accordingly. For example, enabling the `AES256` flag will force the library to use the AES256 algorithm, which is the algorithm used in this module. Therefore, the flags in `aes.h` should look like the following:

```c
//#define AES128 1
//#define AES192 1
#define AES256 1
```

#### Tiny-AES Library Drawbacks

Before diving into the code it's important to be aware of the drawbacks of the tiny-AES library.

1. The library does not support padding. All buffers must be multiples of 16 bytes.
2. The [arrays](https://github.com/kokke/tiny-AES-c/blob/master/aes.c#L79) used in the library can be signatured by security solutions to detect the usage of Tiny-AES. These arrays are used to apply the AES algorithm and therefore are a requirement to have in the code. With that being said, there are ways to modify their signature in order to avoid security solutions detecting the usage of Tiny-AES. One possible solution is to XOR these arrays, for example, to decrypt them at runtime right before calling the initialization function, `AES_init_ctx_iv`.

#### Custom Padding Function

The lack of padding support can be solved by creating a custom padding function as shown in the code snippet below.

```c
BOOL PaddBuffer(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize) {

	PBYTE	PaddedBuffer        = NULL;
	SIZE_T	PaddedSize          = NULL;

	// calculate the nearest number that is multiple of 16 and saving it to PaddedSize
	PaddedSize = InputBufferSize + 16 - (InputBufferSize % 16);
	// allocating buffer of size "PaddedSize"
	PaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
	if (!PaddedBuffer){
		return FALSE;
	}
	// cleaning the allocated buffer
	ZeroMemory(PaddedBuffer, PaddedSize);
	// copying old buffer to new padded buffer
	memcpy(PaddedBuffer, InputBuffer, InputBufferSize);
	//saving results :
	*OutputPaddedBuffer = PaddedBuffer;
	*OutputPaddedSize   = PaddedSize;

	return TRUE;
}
```

## Encryption

```c
#include <Windows.h>
#include <stdio.h>
#include "aes.h"

// "this is plaintext string, we'll try to encrypt... lets hope everything goes well :)" in hex
// since the upper string is 82 byte in size, and 82 is not mulitple of 16, we cant encrypt this directly using tiny-aes
unsigned char Data[] = {
	0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x70, 0x6C, 0x61, 0x6E,
	0x65, 0x20, 0x74, 0x65, 0x78, 0x74, 0x20, 0x73, 0x74, 0x69, 0x6E, 0x67,
	0x2C, 0x20, 0x77, 0x65, 0x27, 0x6C, 0x6C, 0x20, 0x74, 0x72, 0x79, 0x20,
	0x74, 0x6F, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x2E, 0x2E,
	0x2E, 0x20, 0x6C, 0x65, 0x74, 0x73, 0x20, 0x68, 0x6F, 0x70, 0x65, 0x20,
	0x65, 0x76, 0x65, 0x72, 0x79, 0x74, 0x68, 0x69, 0x67, 0x6E, 0x20, 0x67,
	0x6F, 0x20, 0x77, 0x65, 0x6C, 0x6C, 0x20, 0x3A, 0x29, 0x00
};



int main() {
	// struct needed for Tiny-AES library
	struct AES_ctx ctx;


	BYTE pKey[KEYSIZE];                             // KEYSIZE is 32 bytes
	BYTE pIv[IVSIZE];                               // IVSIZE is 16 bytes
		

	srand(time(NULL));                              // the seed to generate the key
	GenerateRandomBytes(pKey, KEYSIZE);             // generating the key bytes
	
	srand(time(NULL) ^ pKey[0]);                    // The seed to generate the IV. Use the first byte of the key to add more randomness.
	GenerateRandomBytes(pIv, IVSIZE);               // Generating the IV

	// Prints both key and IV to the console
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pIv, IVSIZE);

	// Initializing the Tiny-AES Library
	AES_init_ctx_iv(&ctx, pKey, pIv);


	// Initializing variables that will hold the new buffer base address in the case where padding is required and its size
	PBYTE	PaddedBuffer        = NULL;
	SIZE_T	PAddedSize          = NULL;

	// Padding the buffer, if required
	if (sizeof(Data) % 16 != 0){
		PaddBuffer(Data, sizeof(Data), &PaddedBuffer, &PAddedSize);
		// Encrypting the padded buffer instead
		AES_CBC_encrypt_buffer(&ctx, PaddedBuffer, PAddedSize);
		// Printing the encrypted buffer to the console
		PrintHexData("CipherText", PaddedBuffer, PAddedSize);
	}
	// No padding is required, encrypt 'Data' directly
	else {
		AES_CBC_encrypt_buffer(&ctx, Data, sizeof(Data));
		// Printing the encrypted buffer to the console
		PrintHexData("CipherText", Data, sizeof(Data));
	}
	// Freeing PaddedBuffer, if necessary
	if (PaddedBuffer != NULL){
		HeapFree(GetProcessHeap(), 0, PaddedBuffer);
	}
	system("PAUSE");
	return 0;
}
```

## Decryption

```c
#include <Windows.h>
#include <stdio.h>
#include "aes.h"

// Key
unsigned char pKey[] = {
		0x00, 0xB8, 0x80, 0x7E, 0xF0, 0x09, 0x65, 0x8B, 0xD6, 0x6E, 0x2D, 0x8B, 0x0C, 0x6A, 0xA2, 0x34,
		0x42, 0x7A, 0x9D, 0x06, 0xC5, 0x48, 0x6E, 0x22, 0x01, 0x21, 0x7D, 0x5F, 0x44, 0xA9, 0x32, 0x9B };

// IV
unsigned char pIv[] = {
		0x00, 0xB8, 0x80, 0x7E, 0xF0, 0x09, 0x65, 0x8B, 0xD6, 0x6E, 0x2D, 0x8B, 0x0C, 0x6A, 0xA2, 0x34 };

// Encrypted data, multiples of 16 bytes
unsigned char CipherText[] = {
		0xB9, 0x49, 0x12, 0x36, 0xFC, 0xAD, 0x15, 0xDA, 0x27, 0xA2, 0x02, 0xD4, 0x77, 0x8B, 0xBB, 0x4E,
		0xDA, 0xE5, 0x60, 0x71, 0x2F, 0xF4, 0x69, 0x2D, 0x9C, 0x12, 0x8D, 0xD0, 0xA3, 0x0E, 0xB7, 0x26,
		0x21, 0xE4, 0xA4, 0xAD, 0xB3, 0x05, 0xD9, 0x13, 0x8D, 0x2B, 0x0E, 0x0C, 0x21, 0x85, 0xD1, 0xC4,
		0xC1, 0x5A, 0x5F, 0x64, 0xDA, 0x1B, 0xB4, 0x7A, 0x7E, 0x6B, 0xE6, 0x80, 0x17, 0x28, 0x43, 0x4E,
		0xA6, 0x0A, 0x40, 0xB8, 0xBB, 0x1E, 0x27, 0x6A, 0x29, 0xE4, 0x5A, 0xA5, 0x4A, 0x4C, 0xB0, 0xA3,
		0x7D, 0x7A, 0x4E, 0x6D, 0x48, 0x86, 0xEB, 0xB2, 0xFD, 0x1B, 0x21, 0x89, 0xB0, 0x83, 0x14, 0xFE };



int main() {

	// Struct needed for Tiny-AES library
	struct AES_ctx ctx;
	// Initializing the Tiny-AES Library
	AES_init_ctx_iv(&ctx, pKey, pIv);

	// Decrypting
	AES_CBC_decrypt_buffer(&ctx, CipherText, sizeof(CipherText));
	 
	// Print the decrypted buffer to the console
	PrintHexData("PlainText", CipherText, sizeof(CipherText));

	// Print the string
	printf("Data: %s \n", CipherText);

	// exit
	system("PAUSE");
	return 0;
}
```

