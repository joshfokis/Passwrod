// Package passwrod package for password store
package passwrod

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
    "encoding/json"

    "bufio"
	"errors"
	"fmt"
    "io"
	"os"

	// "github.com/vmihailenco/msgpack/v5"
)

// myError func for KISS/DRY error printing
func myError(err error) {
    if err != nil {
        fmt.Printf("%q", err)
    }
}

// Ask function to KISS/DRY for asking user input
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
func (vault *Vault) UnlockVault() os.FileInfo {
    d,e := os.Stat(vault.File)
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

// ClearFile function to write the entry to file
func ClearFile(filename string) {
    var buf []string
    f,_ := os.Open(filename)
    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := scanner.Text()
        buf = append(buf, line)
    }
    for s := 1; s < len(buf); s++ {
        nf, _ := os.OpenFile(filename, os.O_WRONLY, 0666)
        defer nf.Close()
        _, err := nf.WriteString("")
        myError(err)
    }
}

// SaveEntries function to save to file
func (vault *Vault) SaveEntries() string {
    ClearFile(vault.File)

    e, err := json.Marshal(vault.Entries)
	myError(err)
     
    file,err := os.OpenFile(vault.File, os.O_RDWR|os.O_CREATE, 0666)
	myError(err)
    defer file.Close()

    _, err = file.Write(e)
	myError(err)
    
	return "Success"
}
// AddEntry function to write the entry to file
func (vault *Vault) AddEntry(entry PasswordEntry) string {
    vault.Entries = append(vault.Entries, entry)
    vault.SaveEntries()
	return entry.Name
}

// LoadEntries function loads the entries into the Vault
func (vault *Vault) LoadEntries() {
    var entries []PasswordEntry
    file, err := os.Open(vault.File) 
    myError(err)
    defer file.Close()

    jsonParser := json.NewDecoder(file)
    
    _ = jsonParser.Decode(&entries)
    vault.Entries = entries

}

// GetEntry function to retrieve the entries
func (vault *Vault) GetEntry(name string) (int, PasswordEntry) {

    for index, entry := range vault.Entries {
        fmt.Printf("\n%q\n", entry.Name)
        if entry.Name == name {
            // r,_ := json.Marshal(entry) 
            return index, entry
        }
    }
    // fmt.Printf("\n%q\n", entries)
    return 99999, PasswordEntry{
        Name: "Not Found",
        Site: "Not Found",
        Username: "Not Found",
        Password: []byte("Not Found"),
        Category: "Not Found",
    }
}

// UpdateEntry function to retrieve the entries
func (vault *Vault) UpdateEntry(name string) string {
    index, _ := vault.GetEntry(name)

    newEntry := &vault.Entries[index]
    *newEntry = PasswordEntry{
        Name: "Not Found",
        Site: "Not Found",
        Username: "Not Found",
        Password: []byte("Not Found"),
        Category: "Not Found",
    }

    fmt.Printf("\n%q\n", newEntry)
    
    vault.SaveEntries()
	return "Success"
}

// DeleteEntry function to retrieve the entries
func (vault *Vault) DeleteEntry(entry string) string {
    var ents []PasswordEntry
    index, _ := vault.GetEntry(entry)
    for ind, ent := range vault.Entries {
        if ind != index {
           ents = append(ents, ent)
        }
    }
    vault.Entries = ents 
	return "Success"
}
