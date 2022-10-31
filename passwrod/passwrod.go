// Package passwrod package for password store
package passwrod

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"errors"
	"io"	
	"os"

	// "github.com/vmihailenco/msgpack/v5"
)

// Passwrod func for password store
func Passwrod(w string) string {
		fmt.Printf("%v", w)
		return w
}

// UnlockVault func
func UnlockVault(vault string) os.FileInfo {
	d,e := os.Stat(vault)
	if e != nil {
		fmt.Printf("%q", e)
	}
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


// EncryptPasswordbak function to encrypt plaintext password
func EncryptPasswordbak(keyString string, passwordToEncrypt string) (encryptedPassword string) {
	// convert key to bytes
	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(passwordToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
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

// DecryptPasswordbak function to decrypt encrypted password
func DecryptPasswordbak(keyString string, passwordToDecrypt string) string {
	key, _ := hex.DecodeString(keyString)
	ciphertext, _ := base64.URLEncoding.DecodeString(passwordToDecrypt)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}

// WriteEntry function to write the entry to file
func WriteEntry(password string) string {
	return "Success"
}

// GetEntry function to retrieve the entries
func GetEntry(password string) string {
	return "Success"
}
