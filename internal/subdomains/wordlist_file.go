package subdomains

import (
	"bufio"
	"os"
	"strings"
)

// maxWordlistEntries bounds how many custom wordlist labels are kept, so a
// huge file cannot trigger an unbounded number of DNS lookups.
const maxWordlistEntries = 100000

// LoadWordlist reads a newline-delimited subdomain wordlist from path. Blank
// lines and lines beginning with '#' are skipped. Entries are lowercased, a
// trailing root dot is removed, and a fully qualified entry such as
// "www.example.com" is reduced to its leftmost label ("www") so it can be
// appended to the scan domain. Duplicates are dropped in first-seen order.
func LoadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	seen := make(map[string]bool)
	words := make([]string, 0, 1024)
	for scanner.Scan() {
		word := normalize(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		if dot := strings.IndexByte(word, '.'); dot >= 0 {
			word = word[:dot]
		}
		if word == "" || seen[word] {
			continue
		}
		seen[word] = true
		words = append(words, word)
		if len(words) >= maxWordlistEntries {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return words, nil
}
