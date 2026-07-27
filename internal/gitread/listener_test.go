package gitread

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthorizedListenerAcceptsConfiguredUID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "git-read.sock")
	listener, err := ListenUnix(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
		}
		accepted <- acceptErr
	}()
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizedListenerRejectsOtherUIDBeforeHTTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "git-read.sock")
	listener, err := ListenUnix(path, uint32(os.Getuid()+1))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _, _ = listener.Accept() }()
	connection, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, err := connection.Read(buffer); err == nil {
		t.Fatal("unauthorized connection remained open")
	}
}
