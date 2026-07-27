package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/bootstrap"
)

type repositoryBootstrapRemote interface {
	bootstrap.RepositoryRemote
	AuthenticatedLogin(context.Context) (string, error)
}

type bootstrapReceipt struct {
	SchemaVersion int                           `json:"schema_version"`
	PacketDigest  string                        `json:"packet_digest"`
	Account       string                        `json:"account"`
	Repositories  []bootstrap.RepositoryReceipt `json:"repositories"`
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	remote := bootstrap.NewGHRemote(bootstrap.ExecGHRunner{Path: "/usr/bin/gh"})
	if err := run(ctx, os.Args[1:], remote, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, args []string, remote repositoryBootstrapRemote, output io.Writer) error {
	flags := flag.NewFlagSet("gitoversight-bootstrap", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	apply := flags.Bool("apply-repositories", false, "apply the immutable approved repository packet")
	printDigest := flags.Bool("print-packet-digest", false, "print the immutable approved repository packet digest without network access")
	digestFlag := flags.String("packet-digest", "", "SHA-256 digest of the immutable approved repository packet")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse bootstrap arguments: %w", err)
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional bootstrap arguments")
	}
	packet := bootstrap.ApprovedRepositoryPacket()
	digest, err := bootstrap.RepositoryPacketDigest(packet)
	if err != nil {
		return err
	}
	if *printDigest {
		if *apply || *digestFlag != "" {
			return errors.New("--print-packet-digest cannot be combined with mutation flags")
		}
		_, err := fmt.Fprintln(output, digest)
		return err
	}
	if !*apply {
		return errors.New("--apply-repositories is required")
	}
	if *digestFlag == "" || *digestFlag != digest {
		return errors.New("--packet-digest must exactly match the approved immutable repository packet")
	}
	login, err := remote.AuthenticatedLogin(ctx)
	if err != nil {
		return fmt.Errorf("verify authenticated account: %w", err)
	}
	if login != packet.Owner {
		return fmt.Errorf("authenticated account %q does not match approved owner %q", login, packet.Owner)
	}
	receipts, err := bootstrap.ApplyRepositories(ctx, remote, packet)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(bootstrapReceipt{
		SchemaVersion: 1,
		PacketDigest:  digest,
		Account:       login,
		Repositories:  receipts,
	})
}
