package main

import (
	"testing"
	P "passwrod/passwrod"
)

func TestPasswrod(t *testing.T) {
	got := P.Passwrod("Hello, world!")
	want := "Hello, world!"

	if got != want {
		t.Errorf("Got %q, want %q", got, want)
	}
}

func TestUnlockVault(t *testing.T) {
	t.Run("Testing FileName", func(t *testing.T) {
		file := "vault.json"
		
		got := P.UnlockVault(file).Name()
		want := "vault.json"

		if got != want {
			t.Errorf("Got %q, want %q", got, want)
		}
	})
}

func TestEncryptPassword(t *testing.T) {
	t.Run("Testing EncryptPassword", func(t *testing.T) {
		keyString := "Password"
		stringPassword := "mySecretPassword"
		
		got := P.EncryptPassword(keyString,stringPassword)

		want := len(got) == 60 

		if got != want {
			t.Errorf("Got %q, want %q", got, want)
		}
	})
}
