Using `bcrypt.h`

# AES Structure

To start, an `AES` structure is created which contains the required data to perform encryption and decryption.

```c
typedef struct _AES {

	PBYTE	pPlainText;         // base address of the plain text data 
	DWORD	dwPlainSize;        // size of the plain text data

	PBYTE	pCipherText;        // base address of the encrypted data	
	DWORD	dwCipherSize;       // size of it (this can change from dwPlainSize in case there was padding)

	PBYTE	pKey;               // the 32 byte key
	PBYTE	pIv;                // the 16 byte iv

} AES, *PAES;
```

## Encryption Wrapper

```c
// Wrapper function for InstallAesEncryption that makes things easier
BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize) {

	if (pPlainTextData == NULL || sPlainTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;
	
	// Intializing the struct
	AES Aes = {
		.pKey        = pKey,
		.pIv         = pIv,
		.pPlainText  = pPlainTextData,
		.dwPlainSize = sPlainTextSize
	};

	if (!InstallAesEncryption(&Aes)) {
		return FALSE;
	}

	// Saving output
	*pCipherTextData = Aes.pCipherText;
	*sCipherTextSize = Aes.dwCipherSize;

	return TRUE;
}
```

## Decryption Wrapper

```c
// Wrapper function for InstallAesDecryption that make things easier
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

	if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;

	// Intializing the struct
	AES Aes = {
		.pKey          = pKey,
		.pIv           = pIv,
		.pCipherText   = pCipherTextData,
		.dwCipherSize  = sCipherTextSize
	};

	if (!InstallAesDecryption(&Aes)) {
		return FALSE;
	}

	// Saving output
	*pPlainTextData = Aes.pPlainText;
	*sPlainTextSize = Aes.dwPlainSize;

	return TRUE;
}
```

## InstallAesEncryption Function

The `InstallAesEncryption` is the function that performs AES encryption. The function has one parameter, `PAES`, which is a pointer to a populated `AES` structure. The bCrypt library functions used in the function are shown below.

- [BCryptOpenAlgorithmProvider](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider) - Used to load the [BCRYPT_AES_ALGORITHM](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers) Cryptographic Next Generation (CNG) provider to enable the use of cryptographic functions.
- [BCryptGetProperty](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgetproperty) - This function is called twice, the first time to retrieve the value of [BCRYPT_OBJECT_LENGTH](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-property-identifiers) and the second time to fetch the value of [BCRYPT_BLOCK_LENGTH](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-property-identifiers) property identifiers.
- [BCryptSetProperty](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsetproperty) - Used to initialize the `BCRYPT_OBJECT_LENGTH` property identifier.
- [BCryptGenerateSymmetricKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratesymmetrickey) - Used to create a key object from the input AES key specified.
- [BCryptEncrypt](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt) - Used to encrypt a specified block of data. This function is called twice, the first time retrieves the size of the encrypted data to allocate a heap buffer of that size. The second call encrypts the data and stores the ciphertext in the allocated heap.
- [BCryptDestroyKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroykey) - Used to clean up by destroying the key object created using `BCryptGenerateSymmetricKey`.
- [BCryptCloseAlgorithmProvider](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptclosealgorithmprovider) - Used to clean up by closing the object handle of the algorithm provider created earlier using `BCryptOpenAlgorithmProvider`.

```c
// The encryption implementation
BOOL InstallAesEncryption(PAES pAes) {

  BOOL                  bSTATE           = TRUE;
  BCRYPT_ALG_HANDLE     hAlgorithm       = NULL;
  BCRYPT_KEY_HANDLE     hKeyHandle       = NULL;

  ULONG       		cbResult         = NULL;
  DWORD       		dwBlockSize      = NULL;
  
  DWORD       		cbKeyObject      = NULL;
  PBYTE       		pbKeyObject      = NULL;

  PBYTE      		pbCipherText     = NULL;
  DWORD       		cbCipherText     = NULL;


  // Intializing "hAlgorithm" as AES algorithm Handle
  STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later 
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Getting the size of the block used in the encryption. Since this is AES it must be 16 bytes.
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
   	printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Checking if block size is 16 bytes
  if (dwBlockSize != 16) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Allocating memory for the key object 
  pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
  if (pbKeyObject == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
  STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject and will be of size cbKeyObject 
  STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Running BCryptEncrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbCipherText
  STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptEncrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Allocating enough memory for the output buffer, cbCipherText
  pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
  if (pbCipherText == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Running BCryptEncrypt again with pbCipherText as the output buffer
  STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptEncrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }


  // Clean up
_EndOfFunc:
  if (hKeyHandle) 
    	BCryptDestroyKey(hKeyHandle);
  if (hAlgorithm) 
    	BCryptCloseAlgorithmProvider(hAlgorithm, 0);
  if (pbKeyObject) 
    	HeapFree(GetProcessHeap(), 0, pbKeyObject);
  if (pbCipherText != NULL && bSTATE) {
        // If everything worked, save pbCipherText and cbCipherText 
        pAes->pCipherText 	= pbCipherText;
        pAes->dwCipherSize 	= cbCipherText;
  }
  return bSTATE;
}
```

#### InstallAesDecryption Function

The `InstallAesDecryption` is the function that performs AES decryption. The function has one parameter, `PAES`, which is a pointer to a populated `AES` structure. The bCrypt library functions used in the function are the same as in the `InstallAesEncryption` function above, with the only difference being that `BCryptDecrypt` is used instead of `BCryptEncrypt`.

- [BCryptDecrypt](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt) - Used to decrypt a specified block of data. This function is called twice, the first time retrieves the size of the decrypted data to allocate a heap buffer of that size. The second call decrypts the data and stores the plaintext data in the allocated heap.

The function returns `TRUE` if it successfully decrypts the payload, otherwise `FALSE`.

```c
// The decryption implementation
BOOL InstallAesDecryption(PAES pAes) {

  BOOL                  bSTATE          = TRUE;
  BCRYPT_ALG_HANDLE     hAlgorithm      = NULL;
  BCRYPT_KEY_HANDLE     hKeyHandle      = NULL;

  ULONG                 cbResult        = NULL;
  DWORD                 dwBlockSize     = NULL;
  
  DWORD                 cbKeyObject     = NULL;
  PBYTE                 pbKeyObject     = NULL;

  PBYTE                 pbPlainText     = NULL;
  DWORD                 cbPlainText     = NULL;

  // Intializing "hAlgorithm" as AES algorithm Handle
  STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Getting the size of the block used in the encryption. Since this is AES it should be 16 bytes.
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Checking if block size is 16 bytes
  if (dwBlockSize != 16) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Allocating memory for the key object 
  pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
  if (pbKeyObject == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
  STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject of size cbKeyObject 
  STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Running BCryptDecrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbPlainText
  STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Allocating enough memory for the output buffer, cbPlainText
  pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
  if (pbPlainText == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Running BCryptDecrypt again with pbPlainText as the output buffer
  STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Clean up
_EndOfFunc:
  if (hKeyHandle)
    	BCryptDestroyKey(hKeyHandle);
  if (hAlgorithm)
    	BCryptCloseAlgorithmProvider(hAlgorithm, 0);
  if (pbKeyObject)
    	HeapFree(GetProcessHeap(), 0, pbKeyObject);
  if (pbPlainText != NULL && bSTATE) {
        // if everything went well, we save pbPlainText and cbPlainText
        pAes->pPlainText   = pbPlainText;
        pAes->dwPlainSize  = cbPlainText;
  }
  return bSTATE;

}
```

## Helper Functions

```c
// Print the input buffer as a hex char array
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

  printf("unsigned char %s[] = {", Name);

  for (int i = 0; i < Size; i++) {
    	if (i % 16 == 0)
      	    printf("\n\t");
	    
      if (i < Size - 1) {
          printf("0x%0.2X, ", Data[i]);
      } else {
          printf("0x%0.2X ", Data[i]);
      }

  printf("};\n\n\n");
  
}
```

```c
// Generate random bytes of size sSize
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

  for (int i = 0; i < sSize; i++) {
    	pByte[i] = (BYTE)rand() % 0xFF;
  }

}
```

## Usage - Encryption

```c
// The plaintext, in hex format, that will be encrypted
// this is the following string in hex "This is a plain text string, we'll try to encrypt/decrypt !"
unsigned char Data[] = {
	0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x70, 0x6C,
	0x61, 0x69, 0x6E, 0x20, 0x74, 0x65, 0x78, 0x74, 0x20, 0x73, 0x74, 0x72,
	0x69, 0x6E, 0x67, 0x2C, 0x20, 0x77, 0x65, 0x27, 0x6C, 0x6C, 0x20, 0x74,
	0x72, 0x79, 0x20, 0x74, 0x6F, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x2F, 0x64, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x20, 0x21
};

int main() {

	BYTE pKey [KEYSIZE];                    // KEYSIZE is 32 bytes
	BYTE pIv [IVSIZE];                      // IVSIZE is 16 bytes

	srand(time(NULL));                      // The seed to generate the key. This is used to further randomize the key.
	GenerateRandomBytes(pKey, KEYSIZE);     // Generating a key with the helper function
	
	srand(time(NULL) ^ pKey[0]);            // The seed to generate the IV. Use the first byte of the key to add more randomness.
	GenerateRandomBytes(pIv, IVSIZE);       // Generating the IV with the helper function

	// Printing both key and IV onto the console 
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pIv, IVSIZE);

	// Defining two variables the output buffer and its respective size which will be used in SimpleEncryption
	PVOID pCipherText = NULL;
	DWORD dwCipherSize = NULL;
	
	// Encrypting
	if (!SimpleEncryption(Data, sizeof(Data), pKey, pIv, &pCipherText, &dwCipherSize)) {
		return -1;
	}

	// Print the encrypted buffer as a hex array
	PrintHexData("CipherText", pCipherText, dwCipherSize);
	
	// Clean up
	HeapFree(GetProcessHeap(), 0, pCipherText);
	system("PAUSE");
	return 0;
}
```

![[Pasted image 20231220110504.png]]

## Usage - Decryption

The main function below is used to perform the decryption routine. The decryption routine requires the decryption key, IV and ciphertext.

```c
// the key printed to the screen
unsigned char pKey[] = {
		0x3E, 0x31, 0xF4, 0x00, 0x50, 0xB6, 0x6E, 0xB8, 0xF6, 0x98, 0x95, 0x27, 0x43, 0x27, 0xC0, 0x55,
		0xEB, 0xDB, 0xE1, 0x7F, 0x05, 0xFE, 0x65, 0x6D, 0x0F, 0xA6, 0x5B, 0x00, 0x33, 0xE6, 0xD9, 0x0B };

// the iv printed to the screen
unsigned char pIv[] = {
		0xB4, 0xC8, 0x1D, 0x1D, 0x14, 0x7C, 0xCB, 0xFA, 0x07, 0x42, 0xD9, 0xED, 0x1A, 0x86, 0xD9, 0xCD };


// the encrypted buffer printed to the screen, which is:
unsigned char CipherText[] = {
		0x97, 0xFC, 0x24, 0xFE, 0x97, 0x64, 0xDF, 0x61, 0x81, 0xD8, 0xC1, 0x9E, 0x23, 0x30, 0x79, 0xA1,
		0xD3, 0x97, 0x5B, 0xAE, 0x29, 0x7F, 0x70, 0xB9, 0xC1, 0xEC, 0x5A, 0x09, 0xE3, 0xA4, 0x44, 0x67,
		0xD6, 0x12, 0xFC, 0xB5, 0x86, 0x64, 0x0F, 0xE5, 0x74, 0xF9, 0x49, 0xB3, 0x0B, 0xCA, 0x0C, 0x04,
		0x17, 0xDB, 0xEF, 0xB2, 0x74, 0xC2, 0x17, 0xF6, 0x34, 0x60, 0x33, 0xBA, 0x86, 0x84, 0x85, 0x5E };

int main() {

	// Defining two variables the output buffer and its respective size which will be used in SimpleDecryption
	PVOID	pPlaintext  = NULL;
	DWORD	dwPlainSize = NULL;

	// Decrypting
	if (!SimpleDecryption(CipherText, sizeof(CipherText), pKey, pIv, &pPlaintext, &dwPlainSize)) {
		return -1;
	}
	
	// Printing the decrypted data to the screen in hex format
	PrintHexData("PlainText", pPlaintext, dwPlainSize);
	
	// this will print: "This is a plain text string, we'll try to encrypt/decrypt !"
	printf("Data: %s \n", pPlaintext);
	
	// Clean up
	HeapFree(GetProcessHeap(), 0, pPlaintext);
	system("PAUSE");
	return 0;
}

```

![[Pasted image 20231220110602.png]]

