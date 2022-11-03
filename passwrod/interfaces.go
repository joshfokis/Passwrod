package passwrod

// Vaulter is an interface for the vault
type Vaulter interface {
	UnlockVault() 
	LockeVault()
	AddEntry()
	GetEntry()
	DeleteEntry()
	UpdateEntry()
}

