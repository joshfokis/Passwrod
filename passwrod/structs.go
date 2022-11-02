package passwrod

// PasswordEntries struct to layout the form for password entries
type PasswordEntries struct {
	Entries []PasswordEntry
}
// PasswordEntry struct to layout the form for password entries
type PasswordEntry struct {
	Name		string	
	Site		string	
	Username	string 
	Password	[]byte
	Category	string 
}

// Vault struct for password vault file
type Vault struct {
	File string
	MasterPassword []byte
}
