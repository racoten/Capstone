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
	"time"
)

func main() {
	// Parse the command-line flags
	fileType := flag.String("f", "", "the type of file to encrypt (dll, sh, py, cs, or any other type)")
	Name := flag.String("file", "", "the name of the file to encrypt")
	flag.Parse()

	fileName := *Name + "." + *fileType

	// Check that the file type and file name flags are set
	if *fileType == "" || fileName == "" {
		fmt.Println("Usage: go run encrypt.go -f=<file_type> -file=<file_name>")
		return
	}

	// Read the file from disk
	fileBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Check that the file type flag is set correctly
	ext := strings.ToLower(filepath.Ext(fileName))
	switch *fileType {
	case "dll":
		if ext != ".dll" {
			fmt.Printf("Error: expected file with .dll extension, got %s\n", ext)
			return
		}
	case "sh":
		if ext != ".sh" {
			fmt.Printf("Error: expected file with .sh extension, got %s\n", ext)
			return
		}
	case "py":
		if ext != ".py" {
			fmt.Printf("Error: expected file with .py extension, got %s\n", ext)
			return
		}
	case "cs":
		if ext != ".cs" {
			fmt.Printf("Error: expected file with .cs extension, got %s\n", ext)
			return
		}
	default:
		if ext == "" {
			fmt.Println("Error: expected file with an extension")
			return
		}
	}

	// Generate a random initialization vector (IV)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		fmt.Println(err)
		return
	}

	// Generate a random 32-byte key
	randomString := make([]byte, 32)
	if _, err := rand.Read(randomString); err != nil {
		fmt.Println(err)
		return
	}

	// Encrypt the file using the key
	key := []byte(randomString) // key must be at least 32 bytes long
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return
	}

	encryptedFileBytes := make([]byte, len(fileBytes)+aes.BlockSize)
	copy(encryptedFileBytes, iv)
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encryptedFileBytes[aes.BlockSize:], fileBytes)

	// Write the encrypted file to disk
	encryptedFileName := fileName + ".encrypted"
	os.Remove(encryptedFileName)
	time.Sleep(5 * time.Second)
	if err := ioutil.WriteFile(encryptedFileName, encryptedFileBytes, 0644); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Successfully encrypted %s as %s\n", fileName, encryptedFileName)
	fmt.Printf("Key = %x\n", key)
	fmt.Printf("IV = %x", iv)
}
