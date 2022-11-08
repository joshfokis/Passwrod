// Package main for passwrod
package main

import (
	"fmt"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	P "passwrod/passwrod"

)
var docStyle = lipgloss.NewStyle().Margin(1, 2)

type item struct {
	title, desc string
}

func (i item) Title() string       { return i.title }
func (i item) Description() string { return i.desc }
func (i item) FilterValue() string { return i.title }

type model struct {
	list list.Model
}


// VIEW

func (m model) View() string {
	return docStyle.Render(m.list.View())
}

// UPDATE
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}	
	case tea.WindowSizeMsg:
		h, v := docStyle.GetFrameSize()
		m.list.SetSize(msg.Width-h, msg.Height-v)
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// main function for the tui
func (m model) Init() tea.Cmd {
	return nil
}

func main() {
	password := []byte(P.Ask("Please enter your password"))
	items := []list.Item{}

 	vault := P.Vault{
 		MasterPassword: password,
 		File: "vault.json",
 	}

 	 vault.LoadEntries()

	for _, entry := range vault.Entries {
 		items = append(items, item{title: entry.Name, desc: entry.Site})
 	}

	m := model{list: list.New(items, list.NewDefaultDelegate(), 0, 0)}
	m.list.Title = "Password Entries"

	p := tea.NewProgram(
		m, tea.WithAltScreen(),
	)
	
	fmt.Printf("\n%q\n", m.list.Items() )

	if err := p.Start(); err != nil {
		fmt.Printf("\n%q\n",err)
		panic(err)
	}
}

// // Package main for passwrod
// package main
// 
// import (
// 	"flag"
// 	"fmt"
// 	//"os"
// 
// 	P "passwrod/passwrod"
// )
// 
// 
// 
// // main func for passwrod
// func main() {
// 	var password string
// 	var vaultFile string
// 	var entry string
// 	flag.StringVar(&password, "p", "password", "Specify your password")	
// 	flag.StringVar(&vaultFile, "v", "vault.json", "Specify your vault location")	
// 	flag.StringVar(&entry, "e", "Test2", "Specify the entry to look up")	
// 
// // 	password := []byte(P.Ask("Please enter your password"))
// // 	
// 	vault := P.Vault{
// 		MasterPassword: []byte(password),
// 		File: vaultFile,
// 	}
// 	vault.UnlockVault()
// 	vault.LoadEntries()
// 
// 	entries := vault.ListEntries()
// 
// 	_, ent := vault.GetEntry(entry)
// 	fmt.Printf("\n%q\n", entries)
// 	
// 	fmt.Printf("\n%q\n", ent)
// // 	// index, _ := vault.GetEntry("Test3")
// // 
// // 	newEntry := P.PasswordEntry{
// // 		Name: "test",
// // 		Site: "www.example.com",
// // 		Username: "joshfokis",
// // 		Password: []byte("password"),
// // 		Category: "website",
// // 	}
// // 	vault.AddEntry(newEntry)
// // 	vault.DeleteEntry("Test2")
// // 	// fmt.Printf("\n\n found %q", index)
// // 	// vault.UpdateEntry("Test2", index)
// // 	for _, ent := range vault.Entries {
// // 		fmt.Printf("\n%q\n", ent)
// // 	}
// // 	// P.Ask("Please enter your vault location")
// // 	
// // 	// P2Encrypt := P.Ask("enter Password to encrypt: ")
// // 
// // 	
// // 	// encryptedPassword, err := P.EncryptPassword([]byte(P2Encrypt), password)
// // 	// if err != nil {
// // 	// 	fmt.Printf("%q", err)
// // 	// }
// // 	// fmt.Printf("%q", encryptedPassword)
// // 
// // 	// decryptedPassword, err := P.DecryptPassword(encryptedPassword, password)
// // 	// if err != nil {
// // 	// 	fmt.Printf("%q", err)
// // 	// }
// // 	// fmt.Printf("%q", decryptedPassword)
// // 
// // 	// entry := P.PasswordEntry{
// // 	// 	Name: "test",
// // 	// 	Site: "www.example.com",
// // 	// 	Username: "joshfokis",
// // 	// 	Password: "password",
// // 	// 	Category: "website",
// // 	// }
// // 
// // 	// pword, _ := P.EncryptPassword([]byte(P.Ask("Please Enter the Password:\n")), vault.MasterPassword)
// // 
// // // 	entry := P.PasswordEntry{
// // // 		Name: P.Ask("Please enter the name for this entry:\n"),
// // // 		Site: P.Ask("Please enter the Site for this entry:\n"),
// // // 		Username: P.Ask("Please enter the Username for this entry:\n"),
// // // 		Category: P.Ask("Please enter a category for this entry:\n"),
// // // 	} 
// // // 	pword, err := P.EncryptPassword([]byte(P.Ask("Please Enter the Password:\n")), vault.MasterPassword)
// // // 	if err != nil {
// // // 		fmt.Printf("%q", err)
// // // 	}
// // // 	entry.Password = pword
// // // 	fmt.Printf("%q", P.WriteEntry(&entry, &vault))
// }
