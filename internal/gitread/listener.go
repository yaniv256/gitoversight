package gitread

import (
	"net"
	"os"

	"github.com/yaniv256/gitoversight.dev/internal/identity"
)

type authorizedListener struct {
	net.Listener
	allowedUID uint32
}

// ListenUnix creates a protected Unix listener that accepts requests only
// from the configured broker UID. The kernel peer credential check is the
// authorization boundary; socket group permissions are defense in depth.
func ListenUnix(path string, allowedUID uint32) (net.Listener, error) {
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return &authorizedListener{Listener: listener, allowedUID: allowedUID}, nil
}

func (listener *authorizedListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peer, peerErr := identity.FromUnixConn(connection)
		if peerErr == nil && peer.UID == listener.allowedUID {
			return connection, nil
		}
		_ = connection.Close()
	}
}
