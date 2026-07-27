package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"strconv"

	"github.com/yaniv256/gitoversight.dev/internal/checkpoint"
)

func main() {
	statePath := flag.String("state", "", "checkpoint state path")
	keyPath := flag.String("key-file", "", "root-owned checkpoint key path")
	socketPath := flag.String("socket", "", "checkpoint Unix socket path")
	allowedUser := flag.String("allowed-user", "", "service user allowed to extend checkpoints")
	flag.Parse()
	if *statePath == "" || *keyPath == "" || *socketPath == "" || *allowedUser == "" {
		fatal("state, key-file, socket, and allowed-user are required")
	}
	account, err := user.Lookup(*allowedUser)
	if err != nil {
		fatal("lookup allowed user failed")
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		fatal("allowed user UID is invalid")
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		fatal("read key failed")
	}
	signer, err := checkpoint.Open(*statePath, key)
	zero(key)
	if err != nil {
		fatal("open signer failed")
	}
	server := checkpoint.NewServer(*socketPath, signer, uint32(uid))
	listener, err := server.Listen()
	if err != nil {
		fatal("listen failed")
	}
	if err := server.Serve(listener); err != nil {
		fatal("serve failed")
	}
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
