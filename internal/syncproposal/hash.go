package syncproposal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Hash canonically binds the exact public text, derived manifest, rebased head,
// and stored commit packet reviewed by the human.
func Hash(text string, files []string, packetSHA, packetJSON string) string {
	digest := sha256.New()
	write := func(value string) {
		fmt.Fprintf(digest, "%d:", len(value))
		_, _ = digest.Write([]byte(value))
	}
	write(text)
	fmt.Fprintf(digest, "%d|", len(files))
	for _, file := range files {
		write(file)
	}
	write(packetSHA)
	write(packetJSON)
	return hex.EncodeToString(digest.Sum(nil))
}
