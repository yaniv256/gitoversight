package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// runSyncPropose builds the public commit packet from a local revision and
// submits a sync proposal to the broker in one step. The packet head SHA is
// folded into the proposal hash server-side, binding the human's later
// authorization to this exact content.
func runSyncPropose(arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	set := newFlags("sync-propose", stderr)
	remote := addRemoteFlags(set)
	id := set.String("id", "", "sync id (owned)")
	repository := set.String("repository", "", "exact owner/repository of the PRIVATE mirror")
	text := set.String("text", "", "proposal text (public PR body on authorization)")
	textFile := set.String("text-file", "", "read proposal text from a file")
	repositoryPath := set.String("repository-path", "", "local path of the repo holding the export commit")
	revision := set.String("revision", "", "the export commit to publish (single squashed commit)")
	if err := set.Parse(arguments); err != nil {
		return 0, err
	}
	if err := remote.validate(); err != nil {
		return 0, err
	}
	if *id == "" || *repository == "" || *repositoryPath == "" || *revision == "" {
		return 0, errors.New("id, repository, repository-path, and revision are required")
	}
	body := *text
	if *textFile != "" {
		content, err := os.ReadFile(*textFile)
		if err != nil {
			return 0, err
		}
		body = string(content)
	}
	if strings.TrimSpace(body) == "" {
		return 0, errors.New("proposal text is required (-text or -text-file)")
	}
	packet, err := buildCommitPacket(*repositoryPath, *revision)
	if err != nil {
		return 0, err
	}
	packetJSON, err := json.Marshal(packet)
	if err != nil {
		return 0, err
	}
	headSHA, _ := packet["sha"].(string)
	if headSHA == "" {
		return 0, errors.New("commit packet has no head sha")
	}
	payload := map[string]any{
		"id": *id, "repository": *repository, "text": body,
		"commit_packet_json": string(packetJSON), "packet_head_sha": headSHA,
	}
	return signedJSON(client, *remote, http.MethodPost, "/v1/sync", payload, stdout)
}

func runSyncUpdate(arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	set := newFlags("sync-update", stderr)
	remote := addRemoteFlags(set)
	id := set.String("id", "", "sync id")
	text := set.String("text", "", "revised proposal text")
	textFile := set.String("text-file", "", "read revised text from a file")
	repositoryPath := set.String("repository-path", "", "local repo path")
	revision := set.String("revision", "", "revised export commit")
	if err := set.Parse(arguments); err != nil {
		return 0, err
	}
	if err := remote.validate(); err != nil {
		return 0, err
	}
	if *id == "" || *repositoryPath == "" || *revision == "" {
		return 0, errors.New("id, repository-path, and revision are required")
	}
	body := *text
	if *textFile != "" {
		content, err := os.ReadFile(*textFile)
		if err != nil {
			return 0, err
		}
		body = string(content)
	}
	if strings.TrimSpace(body) == "" {
		return 0, errors.New("proposal text is required (-text or -text-file)")
	}
	packet, err := buildCommitPacket(*repositoryPath, *revision)
	if err != nil {
		return 0, err
	}
	packetJSON, err := json.Marshal(packet)
	if err != nil {
		return 0, err
	}
	headSHA, _ := packet["sha"].(string)
	payload := map[string]any{
		"text":               body,
		"commit_packet_json": string(packetJSON), "packet_head_sha": headSHA,
	}
	return signedJSON(client, *remote, http.MethodPost, "/v1/sync/"+url.PathEscape(*id)+"/update", payload, stdout)
}

func runSyncStatus(arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	set := newFlags("sync-status", stderr)
	remote := addRemoteFlags(set)
	id := set.String("id", "", "sync id")
	if err := set.Parse(arguments); err != nil {
		return 0, err
	}
	if err := remote.validate(); err != nil {
		return 0, err
	}
	if *id == "" {
		return 0, errors.New("id is required")
	}
	return signedJSON(client, *remote, http.MethodGet, "/v1/sync/"+url.PathEscape(*id), nil, stdout)
}

func runQueueOrder(arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	set := newFlags("queue-order", stderr)
	remote := addRemoteFlags(set)
	items := set.String("items-json", "", `JSON array: [{"item_id":"q1","kind":"sync","ref":"<sync-id>"}]`)
	if err := set.Parse(arguments); err != nil {
		return 0, err
	}
	if err := remote.validate(); err != nil {
		return 0, err
	}
	var parsed []map[string]any
	if err := json.Unmarshal([]byte(*items), &parsed); err != nil {
		return 0, errors.New("items-json must be a JSON array of {item_id, kind, ref}")
	}
	return signedJSON(client, *remote, http.MethodPost, "/v1/queue/order", map[string]any{"items": parsed}, stdout)
}

func runQueueTop(arguments []string, stdout, stderr io.Writer, client *http.Client) (int, error) {
	set := newFlags("queue-top", stderr)
	remote := addRemoteFlags(set)
	if err := set.Parse(arguments); err != nil {
		return 0, err
	}
	if err := remote.validate(); err != nil {
		return 0, err
	}
	return signedJSON(client, *remote, http.MethodGet, "/v1/queue/top", nil, stdout)
}
