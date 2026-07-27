package adminrpc

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/approval"
	"github.com/yaniv256/gitoversight.dev/internal/identity"
)

const maxMessageBytes = 1 << 20

type request struct {
	SchemaVersion int             `json:"schema_version"`
	Packet        approval.Packet `json:"packet"`
}

type response struct {
	Error string `json:"error,omitempty"`
}

type Client struct {
	path string
}

func NewClient(path string) *Client {
	return &Client{path: path}
}

func (c *Client) Put(packet approval.Packet) error {
	connection, err := net.DialTimeout("unix", c.path, 3*time.Second)
	if err != nil {
		return errors.New("broker approval sink unavailable")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(connection).Encode(request{SchemaVersion: 1, Packet: packet}); err != nil {
		return errors.New("broker approval registration failed")
	}
	var result response
	decoder := json.NewDecoder(io.LimitReader(connection, maxMessageBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return errors.New("broker approval response failed")
	}
	if result.Error != "" {
		return errors.New(result.Error)
	}
	return nil
}

type Server struct {
	path      string
	workerUID uint32
	store     *approval.Store
}

func NewServer(path string, workerUID uint32, store *approval.Store) *Server {
	return &Server{path: path, workerUID: workerUID, store: store}
}

func (s *Server) Listen() (net.Listener, error) {
	_ = os.Remove(s.path)
	listener, err := net.Listen("unix", s.path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

func (s *Server) Serve(listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.handle(connection)
	}
}

func (s *Server) handle(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	peer, err := identity.FromUnixConn(connection)
	if err != nil || peer.UID != s.workerUID {
		s.respond(connection, response{Error: "approval_sink_caller_forbidden"})
		return
	}
	var value request
	decoder := json.NewDecoder(io.LimitReader(connection, maxMessageBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || value.SchemaVersion != 1 {
		s.respond(connection, response{Error: "approval_registration_invalid"})
		return
	}
	if err := s.store.Put(value.Packet); err != nil {
		s.respond(connection, response{Error: "approval_registration_rejected"})
		return
	}
	s.respond(connection, response{})
}

func (s *Server) respond(connection net.Conn, value response) {
	_ = json.NewEncoder(connection).Encode(value)
}
