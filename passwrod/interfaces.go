package passwrod

// Vaulter is an interface for the vault
type Vaulter interface {
	UnlockVault() 
	LockeVault()
	WriteEntry()
	GetEntry()
	DeleteEntry()
	UpdateEntry()
}

