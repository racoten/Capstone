package main

import (
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	// Parse the command-line flags
	fileType := flag.String("f", "", "the type of file to encrypt (dll, sh, py, cs, or any other type)")
	Name := flag.String("file", "", "the name of the file to encrypt")
	flag.Parse()

	fileName := *Name + "." + *fileType

	// Check that the file name flag is set
	if fileName == "" {
		fmt.Println("Usage: go run encrypt.go -file=<file_name>")
		return
	}

	// Read the file from disk
	fileBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Check that the file has an extension
	ext := strings.ToLower(filepath.Ext(fileName))
	if ext == "" {
		fmt.Println("Error: expected file with an extension")
		return
	}

	// Generate a random initialization vector (IV)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		fmt.Println(err)
		return
	}

	// Generate a random 32-byte key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Println(err)
		return
	}

	// Encrypt the file using AES-256 in CFB mode
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return
	}
	encryptedFileBytes := make([]byte, len(fileBytes)+aes.BlockSize)
	copy(encryptedFileBytes, iv)
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encryptedFileBytes[aes.BlockSize:], fileBytes)

	// Encrypt the encrypted file using XOR with the key "superstar"
	xorKey := []byte("superstar")
	for i, b := range encryptedFileBytes {
		encryptedFileBytes[i] = b ^ xorKey[i%len(xorKey)]
	}

	// Write the encrypted file to disk
	encryptedFileName := fileName + ".GO_CHAIN.encrypted"
	os.Remove(encryptedFileName)
	if err := ioutil.WriteFile(encryptedFileName, encryptedFileBytes, 0644); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Successfully encrypted %s as %s\n", fileName, encryptedFileName)
	fmt.Printf("Key = %x\n", key)
	fmt.Printf("IV = %x\n", iv)
}
