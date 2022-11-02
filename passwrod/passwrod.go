// Package passwrod package for password store
package passwrod

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
    "encoding/json"

	"errors"
	"fmt"
    "io"
	"os"

	// "github.com/vmihailenco/msgpack/v5"
)

// myError func for KISS error printing
func myError(err error) {
    if err != nil {
        fmt.Printf("%q", err)
    }
}

// Ask function to KISS for asking user input
func Ask(question string) string {
	var word string
	fmt.Println(question)
	fmt.Scanln(&word)
	return word
}
// Passwrod func for password store
func Passwrod(w string) string {
    fmt.Printf("%v", w)
    return w
}

// UnlockVault func
func UnlockVault(vault string) os.FileInfo {
	d,e := os.Stat(vault)
	myError(e)
	
	fmt.Printf("%q", d)
	return d
}

// LockVault func
func LockVault(vault string) os.FileInfo {
	d,e := os.Stat(vault)
	myError(e)
	
	fmt.Printf("%q", d.Name())
	return d
}

// EncryptVault function to encrypt the vault file
func EncryptVault(vault string) string {
	return "Success"
}

// DecryptVault function to decrypt the vault file
func DecryptVault(vault string) string {
	return "Success"
}

// EncryptPassword encrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func EncryptPassword(plaintext []byte, key []byte) (ciphertext []byte, err error) {
    k := sha256.Sum256(key)
    block, err := aes.NewCipher(k[:])
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    _, err = io.ReadFull(rand.Reader, nonce)
    if err != nil {
        return nil, err
    }

    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptPassword decrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func DecryptPassword(ciphertext []byte, key []byte) (plaintext []byte, err error) {
    k := sha256.Sum256(key)
    block, err := aes.NewCipher(k[:])
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    if len(ciphertext) < gcm.NonceSize() {
        return nil, errors.New("malformed ciphertext")
    }

    return gcm.Open(nil,
        ciphertext[:gcm.NonceSize()],
        ciphertext[gcm.NonceSize():],
        nil,
    )
}

// WriteEntry function to write the entry to file
func (vault Vault) WriteEntry(entry *PasswordEntry) string {

    e, err := json.Marshal(entry)
	myError(err)
     
    file,err := os.OpenFile(vault.File, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	myError(err)
    defer file.Close()

    _, err = file.Write(e)
	myError(err)
    
	return entry.Name
}

// GetEntry function to retrieve the entries
func (vault Vault) GetEntry(name string) string {
    var entries []PasswordEntry
    file, err := os.Open(vault.File) 
    myError(err)
    defer file.Close()

    jsonParser := json.NewDecoder(file)
    
    _ = jsonParser.Decode(&entries)
    
    for _, entry := range entries {
        fmt.Printf("\n%q\n", entry.Name)
        if entry.Name == name {
            return entry.Name
        }
    }
    // fmt.Printf("\n%q\n", entries)
    return ""
}

// UpdateEntry function to retrieve the entries
func UpdateEntry(password string) string {
	return "Success"
}

// DeleteEntry function to retrieve the entries
func DeleteEntry(password string) string {
	return "Success"
}
