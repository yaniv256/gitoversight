package mutation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

type Packet struct {
	RequestID    string         `json:"request_id"`
	Repository   string         `json:"repository"`
	Operation    string         `json:"operation"`
	Branch       string         `json:"branch,omitempty"`
	Title        string         `json:"title,omitempty"`
	Body         string         `json:"body,omitempty"`
	ManifestHash string         `json:"manifest_hash,omitempty"`
	ActorMode    string         `json:"actor_mode"`
	ActorSubject string         `json:"actor_subject,omitempty"`
	Payload      map[string]any `json:"payload,omitempty"`
}

func Hash(packet Packet) (string, error) {
	payload, err := json.Marshal(packet)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}
