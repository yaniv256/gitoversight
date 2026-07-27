package identity

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

type Peer struct {
	PID int32
	UID uint32
	GID uint32
}

type Registry struct {
	byUID map[uint32]string
}

func NewRegistry(agents map[string]uint32) (*Registry, error) {
	registry := &Registry{byUID: make(map[uint32]string, len(agents))}
	for name, uid := range agents {
		if name == "" {
			return nil, errors.New("agent name is required")
		}
		if other, exists := registry.byUID[uid]; exists {
			return nil, fmt.Errorf("agents %s and %s share uid %d", other, name, uid)
		}
		registry.byUID[uid] = name
	}
	return registry, nil
}

func (r *Registry) AgentForUID(uid uint32) (string, bool) {
	name, ok := r.byUID[uid]
	return name, ok
}

func FromUnixConn(conn net.Conn) (Peer, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}, errors.New("connection is not a Unix socket")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var credentials *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return Peer{}, err
	}
	if controlErr != nil {
		return Peer{}, controlErr
	}
	return Peer{PID: credentials.Pid, UID: credentials.Uid, GID: credentials.Gid}, nil
}
