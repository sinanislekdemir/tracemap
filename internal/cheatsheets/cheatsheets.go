// Package cheatsheets holds the static interactive-TCP protocol reference shown
// in the netcat cheatsheet window. The data is embedded and never sends traffic.
package cheatsheets

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

//go:embed cheatsheets.json
var raw []byte

// Command is one labelled example a user can copy into a session.
type Command struct {
	Label   string `json:"label"`
	Command string `json:"command"`
	Note    string `json:"note,omitempty"`
}

// Group is a titled block of commands.
type Group struct {
	Name     string    `json:"name"`
	Commands []Command `json:"commands"`
}

// Sheet is one protocol reference.
type Sheet struct {
	ID       string  `json:"id"`
	Title    string  `json:"title"`
	Protocol string  `json:"protocol"`
	Port     string  `json:"port"`
	Summary  string  `json:"summary"`
	Groups   []Group `json:"groups"`
}

var (
	once   sync.Once
	sheets []Sheet
	byID   map[string]*Sheet
)

func load() {
	once.Do(func() {
		if err := json.Unmarshal(raw, &sheets); err != nil {
			panic(fmt.Sprintf("cheatsheets: %v", err))
		}
		byID = make(map[string]*Sheet, len(sheets))
		for i := range sheets {
			byID[sheets[i].ID] = &sheets[i]
		}
	})
}

// All returns every sheet.
func All() []Sheet {
	load()
	return sheets
}

// Find returns the sheet with the given id, or nil.
func Find(id string) *Sheet {
	load()
	return byID[id]
}
