package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/yaniv256/gitoversight.dev/internal/checkpoint"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

func main() {
	database := flag.String("database", "", "restored SQLite database")
	statePath := flag.String("checkpoint-state", "", "restored signed checkpoint")
	keyPath := flag.String("checkpoint-key", "", "checkpoint HMAC key")
	tenant := flag.String("tenant", "", "expected tenant")
	flag.Parse()
	if *database == "" || *statePath == "" || *keyPath == "" || *tenant == "" {
		fatal("database, checkpoint-state, checkpoint-key, and tenant are required")
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		fatal("read checkpoint key: %v", err)
	}
	signer, err := checkpoint.Open(*statePath, key)
	zero(key)
	if err != nil {
		fatal("verify checkpoint signature: %v", err)
	}
	state := signer.State()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, sqlite.Config{Path: *database})
	if err != nil {
		fatal("open restored database: %v", err)
	}
	defer db.Close()
	if err := db.VerifyAuthorityAuditChain(ctx, *tenant); err != nil {
		fatal("verify restored audit chain: %v", err)
	}
	policy, err := db.LatestPolicyGeneration(ctx, *tenant)
	if err != nil {
		fatal("read restored policy generation: %v", err)
	}
	events, err := db.AuthorityAuditTrail(ctx, *tenant)
	if err != nil {
		fatal("read restored audit trail: %v", err)
	}
	tail := "GENESIS"
	if len(events) != 0 {
		tail = events[len(events)-1].Hash
	}
	if state.Tail != tail || state.PolicyGeneration != policy.Generation {
		fatal("signed checkpoint does not bind restored authority state")
	}
	if state.Sequence == 0 || state.Signature == "" {
		fatal("restored checkpoint is unsigned")
	}
	fmt.Println("restored authority chain and signed checkpoint verified")
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func fatal(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
