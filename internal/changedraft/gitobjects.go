package changedraft

import (
	"crypto/sha1" // Git object identity is defined by SHA-1 for these repositories.
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type TreeObject struct {
	Name      string
	Mode      string
	Object    ObjectID
	Directory bool
}

type GitObjectBuilder struct{}

func (GitObjectBuilder) Blob(content []byte) ObjectID {
	return GitObjectID("blob", content)
}

func (GitObjectBuilder) Tree(entries []TreeObject) (ObjectID, error) {
	copy := append([]TreeObject(nil), entries...)
	sort.Slice(copy, func(i, j int) bool {
		left, right := copy[i].Name, copy[j].Name
		if copy[i].Directory {
			left += "/"
		}
		if copy[j].Directory {
			right += "/"
		}
		return left < right
	})
	payload := make([]byte, 0, len(copy)*48)
	for _, entry := range copy {
		if entry.Name == "" || strings.ContainsAny(entry.Name, "/\x00") || !validObjectID(entry.Object) {
			return "", ErrInvalidSnapshot
		}
		mode := entry.Mode
		if entry.Directory {
			mode = "40000"
		} else if !validMode(Mode(mode)) {
			return "", ErrUnsupportedMode
		}
		object, _ := hex.DecodeString(string(entry.Object))
		payload = append(payload, mode...)
		payload = append(payload, ' ')
		payload = append(payload, entry.Name...)
		payload = append(payload, 0)
		payload = append(payload, object...)
	}
	return GitObjectID("tree", payload), nil
}

func GitObjectID(kind string, content []byte) ObjectID {
	header := []byte(kind + " " + strconv.Itoa(len(content)) + "\x00")
	hash := sha1.New() // #nosec G401 -- compatibility with the Git object format.
	_, _ = hash.Write(header)
	_, _ = hash.Write(content)
	return ObjectID(hex.EncodeToString(hash.Sum(nil)))
}

type treeNode struct {
	files map[string]Entry
	dirs  map[string]*treeNode
}

func buildRootTree(entries []Entry, objects ObjectBuilder) (ObjectID, error) {
	root := &treeNode{files: map[string]Entry{}, dirs: map[string]*treeNode{}}
	for _, entry := range entries {
		parts := strings.Split(entry.Path, "/")
		node := root
		for _, component := range parts[:len(parts)-1] {
			if _, file := node.files[component]; file {
				return "", ErrPathConflict
			}
			child := node.dirs[component]
			if child == nil {
				child = &treeNode{files: map[string]Entry{}, dirs: map[string]*treeNode{}}
				node.dirs[component] = child
			}
			node = child
		}
		name := parts[len(parts)-1]
		if _, directory := node.dirs[name]; directory {
			return "", ErrPathConflict
		}
		node.files[name] = entry
	}
	return root.objectID(objects)
}

func (n *treeNode) objectID(objects ObjectBuilder) (ObjectID, error) {
	entries := make([]TreeObject, 0, len(n.files)+len(n.dirs))
	for name, file := range n.files {
		entries = append(entries, TreeObject{Name: name, Mode: string(file.Mode), Object: file.Object})
	}
	for name, child := range n.dirs {
		object, err := child.objectID(objects)
		if err != nil {
			return "", fmt.Errorf("tree %s: %w", name, err)
		}
		entries = append(entries, TreeObject{Name: name, Mode: "40000", Object: object, Directory: true})
	}
	return objects.Tree(entries)
}
