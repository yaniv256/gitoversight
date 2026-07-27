package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/commitpacket"
)

var gitIdentityPattern = regexp.MustCompile(`^(.*) <([^>]+)> ([0-9]+) ([+-][0-9]{4})$`)

func buildCommitPacket(repositoryPath, revision string) (map[string]any, error) {
	commitSHA, err := gitOutput(repositoryPath, "rev-parse", revision+"^{commit}")
	if err != nil {
		return nil, err
	}
	rawCommit, err := gitBytes(repositoryPath, "cat-file", "commit", commitSHA)
	if err != nil {
		return nil, err
	}
	commit, err := parseCommit(rawCommit, commitSHA)
	if err != nil {
		return nil, err
	}
	// A pre-PR's base is the PUBLIC repository's HEAD, which this process cannot
	// see: policy resolves the private->public mapping broker-side, and an agent
	// that could name its own base could redirect a sync at a repository nobody
	// authorized. So the CLI sends the complete SHAPE of the revision and the
	// broker computes the delta against the real base.
	//
	// This also means a path the shape omits is a deletion, which a
	// parent-relative delta could never express — the reason multi-commit syncs
	// used to be impossible.
	entries, blobSHAs, err := readTreeEntries(repositoryPath, commitSHA)
	if err != nil {
		return nil, err
	}
	blobs, err := readBlobsBatch(repositoryPath, blobSHAs)
	if err != nil {
		return nil, err
	}
	packet := commitpacket.Packet{Blobs: blobs, Tree: commitpacket.Tree{SHA: commit.Tree, Entries: entries}, Commit: commit}
	if err := packet.Validate(); err != nil {
		return nil, fmt.Errorf("local commit exceeds publication contract: %w", err)
	}
	return map[string]any{"sha": commitSHA, "object_package": packet}, nil
}

// submoduleMode is the git tree mode for a gitlink (submodule pointer). Its tree
// entry carries a commit SHA resolved from the submodule's own repo — no blob.
const submoduleMode = "160000"

func supportedBlobMode(mode string) bool {
	switch mode {
	case "100644", "100755", "120000":
		return true
	default:
		return false
	}
}

func readTreeEntries(repositoryPath, commitSHA string) ([]commitpacket.TreeEntry, []string, error) {
	command := exec.Command("git", "ls-tree", "-rz", "--full-tree", commitSHA)
	command.Dir = repositoryPath
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := command.Start(); err != nil {
		return nil, nil, err
	}
	fail := func(cause error) ([]commitpacket.TreeEntry, []string, error) {
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, nil, cause
	}

	reader := bufio.NewReaderSize(stdout, commitpacket.MaxPathBytes+256)
	entries := make([]commitpacket.TreeEntry, 0)
	seenBlobs := make(map[string]struct{})
	blobSHAs := make([]string, 0)
	totalPathBytes := 0
	for {
		row, readErr := reader.ReadSlice(0)
		if errors.Is(readErr, io.EOF) && len(row) == 0 {
			break
		}
		if readErr != nil {
			return fail(errors.New("git tree entry exceeds publication bounds"))
		}
		row = row[:len(row)-1]
		metadata, path, found := bytes.Cut(row, []byte{'\t'})
		fields := strings.Fields(string(metadata))
		if !found || len(fields) != 3 || len(path) > commitpacket.MaxPathBytes {
			return fail(errors.New("git tree contains an unsupported entry"))
		}
		// A gitlink (submodule pointer) is type "commit" at mode 160000 and names
		// a commit in the submodule's OWN repository — GitHub resolves it by SHA
		// and there is no blob to upload. Everything else must be a blob.
		isSubmodule := fields[1] == "commit" && fields[0] == submoduleMode
		if !isSubmodule && (fields[1] != "blob" || !supportedBlobMode(fields[0])) {
			return fail(errors.New("git tree contains an unsupported entry"))
		}
		if len(entries) >= commitpacket.MaxTreeEntries {
			return fail(errors.New("git tree exceeds publication entry bounds"))
		}
		totalPathBytes += len(path)
		if totalPathBytes > commitpacket.MaxTreePathBytes {
			return fail(errors.New("git tree paths exceed publication bounds"))
		}
		entry := commitpacket.TreeEntry{Mode: fields[0], Type: fields[1], SHA: fields[2], Path: string(path)}
		entries = append(entries, entry)
		if isSubmodule {
			continue
		}
		if _, exists := seenBlobs[entry.SHA]; !exists {
			seenBlobs[entry.SHA] = struct{}{}
			blobSHAs = append(blobSHAs, entry.SHA)
		}
	}
	if err := command.Wait(); err != nil {
		return nil, nil, fmt.Errorf("git ls-tree: %w", err)
	}
	return entries, blobSHAs, nil
}

func readBlobsBatch(repositoryPath string, shas []string) ([]commitpacket.Blob, error) {
	command := exec.Command("git", "cat-file", "--batch")
	command.Dir = repositoryPath
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	fail := func(cause error) ([]commitpacket.Blob, error) {
		_ = stdin.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
		return nil, cause
	}

	reader := bufio.NewReader(stdout)
	blobs := make([]commitpacket.Blob, 0, len(shas))
	total := 0
	for _, expectedSHA := range shas {
		if _, err := io.WriteString(stdin, expectedSHA+"\n"); err != nil {
			return fail(fmt.Errorf("git cat-file request: %w", err))
		}
		header, err := reader.ReadString('\n')
		if err != nil {
			return fail(fmt.Errorf("git cat-file header: %w", err))
		}
		fields := strings.Fields(header)
		if len(fields) != 3 || fields[0] != expectedSHA || fields[1] != "blob" {
			return fail(errors.New("git cat-file returned an unexpected object"))
		}
		size, err := strconv.Atoi(fields[2])
		if err != nil || size < 0 || size > commitpacket.MaxBlobBytes || total+size > commitpacket.MaxTotalBytes {
			return fail(errors.New("local commit exceeds publication blob bounds"))
		}
		content := make([]byte, size)
		if _, err := io.ReadFull(reader, content); err != nil {
			return fail(fmt.Errorf("git cat-file content: %w", err))
		}
		terminator, err := reader.ReadByte()
		if err != nil || terminator != '\n' {
			return fail(errors.New("git cat-file returned a malformed object"))
		}
		total += size
		blobs = append(blobs, commitpacket.Blob{SHA: expectedSHA, Content: base64.StdEncoding.EncodeToString(content), Encoding: "base64"})
	}
	if err := stdin.Close(); err != nil {
		return fail(fmt.Errorf("git cat-file close: %w", err))
	}
	if err := command.Wait(); err != nil {
		return nil, fmt.Errorf("git cat-file: %w", err)
	}
	return blobs, nil
}

func parseCommit(raw []byte, sha string) (commitpacket.Commit, error) {
	sections := bytes.SplitN(raw, []byte("\n\n"), 2)
	if len(sections) != 2 {
		return commitpacket.Commit{}, errors.New("git commit object is malformed")
	}
	commit := commitpacket.Commit{SHA: sha, Message: string(sections[1])}
	for _, line := range strings.Split(string(sections[0]), "\n") {
		key, value, found := strings.Cut(line, " ")
		if !found {
			continue
		}
		switch key {
		case "tree":
			if commit.Tree != "" {
				return commitpacket.Commit{}, errors.New("git commit contains duplicate tree headers")
			}
			commit.Tree = value
		case "parent":
			commit.Parents = append(commit.Parents, value)
		case "author":
			var err error
			commit.Author, err = parseGitIdentity(value)
			if err != nil {
				return commitpacket.Commit{}, err
			}
		case "committer":
			var err error
			commit.Committer, err = parseGitIdentity(value)
			if err != nil {
				return commitpacket.Commit{}, err
			}
		}
	}
	if commit.Tree == "" {
		return commitpacket.Commit{}, errors.New("git commit is missing its tree")
	}
	return commit, nil
}

func parseGitIdentity(value string) (commitpacket.Signature, error) {
	match := gitIdentityPattern.FindStringSubmatch(value)
	if match == nil {
		return commitpacket.Signature{}, errors.New("git commit identity is malformed")
	}
	seconds, err := strconv.ParseInt(match[3], 10, 64)
	if err != nil {
		return commitpacket.Signature{}, errors.New("git commit timestamp is malformed")
	}
	sign := 1
	if match[4][0] == '-' {
		sign = -1
	}
	hours, _ := strconv.Atoi(match[4][1:3])
	minutes, _ := strconv.Atoi(match[4][3:5])
	zone := time.FixedZone("git", sign*(hours*60+minutes)*60)
	return commitpacket.Signature{Name: match[1], Email: match[2], Date: time.Unix(seconds, 0).In(zone).Format(time.RFC3339)}, nil
}

func gitOutput(directory string, arguments ...string) (string, error) {
	value, err := gitBytes(directory, arguments...)
	return strings.TrimSpace(string(value)), err
}

func gitBytes(directory string, arguments ...string) ([]byte, error) {
	command := exec.Command("git", arguments...)
	command.Dir = directory
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(arguments, " "), err)
	}
	return output, nil
}
