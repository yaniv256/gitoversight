package checkpoint

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/identity"
)

const maxRequestBytes = 16 << 10

type serviceRequest struct {
	Operation string     `json:"operation"`
	Extension *Extension `json:"extension,omitempty"`
	State     *State     `json:"state,omitempty"`
}

type serviceResponse struct {
	State *State `json:"state,omitempty"`
	Error string `json:"error,omitempty"`
}

type Server struct {
	path       string
	signer     *Signer
	allowedUID uint32
}

func NewServer(path string, signer *Signer, allowedUID uint32) *Server {
	return &Server{path: path, signer: signer, allowedUID: allowedUID}
}

func (s *Server) SocketPath() string { return s.path }

func (s *Server) Listen() (net.Listener, error) {
	if s.path == "" || s.signer == nil {
		return nil, errors.New("checkpoint server configuration is incomplete")
	}
	_ = os.Remove(s.path)
	listener, err := net.Listen("unix", s.path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(s.path, 0o660); err != nil {
		_ = listener.Close()
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
		s.handle(connection)
	}
}

func (s *Server) handle(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	var request serviceRequest
	decoder := json.NewDecoder(io.LimitReader(connection, maxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		s.respond(connection, serviceResponse{Error: "invalid checkpoint request"})
		return
	}
	if !socketPermissionsValid(s.path) {
		s.respond(connection, serviceResponse{Error: "checkpoint socket permissions invalid"})
		return
	}
	peer, err := identity.FromUnixConn(connection)
	if err != nil || peer.UID != s.allowedUID {
		s.respond(connection, serviceResponse{Error: "unauthorized checkpoint peer"})
		return
	}
	switch request.Operation {
	case "extend":
		if request.Extension == nil || request.State != nil {
			s.respond(connection, serviceResponse{Error: "invalid checkpoint extension"})
			return
		}
		state, err := s.signer.Extend(*request.Extension)
		if err != nil {
			s.respond(connection, serviceResponse{Error: err.Error()})
			return
		}
		s.respond(connection, serviceResponse{State: &state})
	case "state":
		if request.Extension != nil || request.State != nil {
			s.respond(connection, serviceResponse{Error: "invalid checkpoint state request"})
			return
		}
		state := s.signer.State()
		s.respond(connection, serviceResponse{State: &state})
	case "verify":
		if request.State == nil || request.Extension != nil {
			s.respond(connection, serviceResponse{Error: "invalid checkpoint verification"})
			return
		}
		if err := s.signer.Verify(*request.State); err != nil {
			s.respond(connection, serviceResponse{Error: err.Error()})
			return
		}
		s.respond(connection, serviceResponse{})
	default:
		s.respond(connection, serviceResponse{Error: "unsupported checkpoint operation"})
	}
}

func socketPermissionsValid(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0o660
}

func (s *Server) respond(connection net.Conn, response serviceResponse) {
	_ = json.NewEncoder(connection).Encode(response)
}

type Client struct {
	path    string
	timeout time.Duration
}

func NewClient(path string, timeout time.Duration) (*Client, error) {
	if path == "" || timeout <= 0 {
		return nil, errors.New("checkpoint client configuration is incomplete")
	}
	return &Client{path: path, timeout: timeout}, nil
}

func (c *Client) SocketPath() string { return c.path }

func (c *Client) Extend(extension Extension) (State, error) {
	response, err := c.call(serviceRequest{Operation: "extend", Extension: &extension})
	if err != nil {
		return State{}, err
	}
	if response.State == nil {
		return State{}, errors.New("checkpoint response omitted state")
	}
	return *response.State, nil
}

func (c *Client) State() (State, error) {
	response, err := c.call(serviceRequest{Operation: "state"})
	if err != nil {
		return State{}, err
	}
	if response.State == nil {
		return State{}, errors.New("checkpoint response omitted state")
	}
	return *response.State, nil
}

func (c *Client) Verify(state State) error {
	_, err := c.call(serviceRequest{Operation: "verify", State: &state})
	return err
}

func (c *Client) call(request serviceRequest) (serviceResponse, error) {
	connection, err := net.DialTimeout("unix", c.path, c.timeout)
	if err != nil {
		return serviceResponse{}, fmt.Errorf("checkpoint unavailable: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(c.timeout))
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return serviceResponse{}, fmt.Errorf("checkpoint request failed: %w", err)
	}
	var response serviceResponse
	decoder := json.NewDecoder(io.LimitReader(connection, maxRequestBytes))
	if err := decoder.Decode(&response); err != nil {
		return serviceResponse{}, fmt.Errorf("checkpoint response failed: %w", err)
	}
	if response.Error != "" {
		return serviceResponse{}, errors.New(response.Error)
	}
	return response, nil
}
