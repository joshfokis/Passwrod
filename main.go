// Package main for passwrod
package main

import (
	"fmt"

	P "passwrod/passwrod"
)

// Ask function to KISS for asking user input
func Ask(question string) string {
	var word string
	fmt.Println(question)
	fmt.Scanln(&word)
	return word
}

// main func for passwrod
func main() {
	// password := []byte(Ask("Please enter your password"))
	
	//vault := Ask("Please enter your vault location")
	
	// P2Encrypt := Ask("enter Password to encrypt: ")

	
	// encryptedPassword, err := P.EncryptPassword([]byte(P2Encrypt), password)
	// if err != nil {
	// 	fmt.Printf("%q", err)
	// }
	// fmt.Printf("%q", encryptedPassword)

	// decryptedPassword, err := P.DecryptPassword(encryptedPassword, password)
	// if err != nil {
	// 	fmt.Printf("%q", err)
	// }
	// fmt.Printf("%q", decryptedPassword)

	entry := P.PasswordEntry{
		Name: "test",
		Site: "www.example.com",
		Username: "joshfokis",
		Password: "password",
		Category: "website",
	}

	fmt.Printf("%q", P.WriteEntry(&entry))
}
