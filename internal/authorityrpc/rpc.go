package authorityrpc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/identity"
	"github.com/yaniv256/gitoversight.dev/internal/server"
)

const (
	maxMessageBytes      = 32 << 10
	maxConnections       = 64
	clientRequestTimeout = 5 * time.Second
	serverRequestTimeout = 4 * time.Second
)

type request struct {
	Action       string    `json:"action"`
	Token        string    `json:"token"`
	TenantID     string    `json:"tenant_id,omitempty"`
	RequestID    string    `json:"request_id,omitempty"`
	Repository   string    `json:"repository,omitempty"`
	Operation    string    `json:"operation,omitempty"`
	MutationHash string    `json:"mutation_hash,omitempty"`
	DeliveryID   string    `json:"delivery_id,omitempty"`
	Outcome      string    `json:"outcome,omitempty"`
	ResourceID   string    `json:"resource_id,omitempty"`
	Reason       string    `json:"reason,omitempty"`
	At           time.Time `json:"at"`
}

type response struct {
	Capability server.Capability `json:"capability,omitempty"`
	Error      string            `json:"error,omitempty"`
}

type Client struct{ path string }

func NewClient(path string) *Client { return &Client{path: path} }

func (client *Client) ConsumeCapability(token, repository, operation, mutationHash string, now time.Time) (server.Capability, error) {
	deliveryID, err := newDeliveryID()
	if err != nil {
		return server.Capability{}, errors.New("authority delivery id unavailable")
	}
	value := request{Action: "consume", Token: token, Repository: repository, Operation: operation, MutationHash: mutationHash, DeliveryID: deliveryID, At: now}
	result, err := client.call(value)
	if err != nil {
		// A lost response can occur after durable consumption. The broker permits
		// the same worker to retrieve that exact still-active grant idempotently.
		result, err = client.call(value)
	}
	return result.Capability, err
}

func newDeliveryID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func (client *Client) FinalizeCapability(token, outcome, resourceID, reason string, now time.Time) error {
	_, err := client.call(request{Action: "finalize", Token: token, Outcome: outcome, ResourceID: resourceID, Reason: reason, At: now})
	return err
}

func (client *Client) AuthorizeReconciliation(tenantID, requestID, repository, operation, mutationHash string, now time.Time) (server.Capability, error) {
	result, err := client.call(request{Action: "authorize_reconciliation", TenantID: tenantID, RequestID: requestID, Repository: repository, Operation: operation, MutationHash: mutationHash, At: now})
	return result.Capability, err
}

func (client *Client) FinalizeReconciliation(tenantID, requestID, outcome, resourceID string, now time.Time) error {
	_, err := client.call(request{Action: "finalize_reconciliation", TenantID: tenantID, RequestID: requestID, Outcome: outcome, ResourceID: resourceID, At: now})
	return err
}

func (client *Client) call(value request) (response, error) {
	connection, err := net.DialTimeout("unix", client.path, time.Second)
	if err != nil {
		return response{}, errors.New("authority service unavailable")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(clientRequestTimeout))
	requestErr := json.NewEncoder(connection).Encode(value)
	var result response
	decoder := json.NewDecoder(io.LimitReader(connection, maxMessageBytes))
	decoder.DisallowUnknownFields()
	responseErr := decoder.Decode(&result)
	if requestErr != nil {
		if responseErr == nil && result.Error != "" {
			return result, errors.New(result.Error)
		}
		return response{}, errors.New("authority request failed")
	}
	if responseErr != nil {
		return response{}, errors.New("authority response failed")
	}
	if result.Error != "" {
		return result, errors.New(result.Error)
	}
	return result, nil
}

type Server struct {
	path      string
	broker    *server.DurableBroker
	workerUID uint32
	workerID  string
	socketGID int
}

func NewServer(path string, broker *server.DurableBroker, workerUID uint32, workerID string, socketGID int) *Server {
	return &Server{path: path, broker: broker, workerUID: workerUID, workerID: workerID, socketGID: socketGID}
}

func (service *Server) Listen() (net.Listener, error) {
	if service.path == "" || service.broker == nil || service.workerID == "" || service.socketGID < 0 {
		return nil, errors.New("authority RPC configuration is incomplete")
	}
	_ = os.Remove(service.path)
	listener, err := net.Listen("unix", service.path)
	if err != nil {
		return nil, err
	}
	if err := os.Chown(service.path, -1, service.socketGID); err != nil {
		_ = listener.Close()
		return nil, err
	}
	if err := os.Chmod(service.path, 0o660); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func (service *Server) Serve(listener net.Listener) error {
	connections := make(chan struct{}, maxConnections)
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		connections <- struct{}{}
		go func() {
			defer func() { <-connections }()
			service.handle(connection)
		}()
	}
}

func (service *Server) handle(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(serverRequestTimeout))
	if !service.socketPermissionsValid() {
		service.respond(connection, response{Error: "authority_socket_permissions_invalid"})
		return
	}
	peer, err := identity.FromUnixConn(connection)
	if err != nil || peer.UID != service.workerUID {
		service.respond(connection, response{Error: "authority_caller_forbidden"})
		return
	}
	var value request
	decoder := json.NewDecoder(io.LimitReader(connection, maxMessageBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || value.At.IsZero() {
		service.respond(connection, response{Error: "authority_request_invalid"})
		return
	}
	switch value.Action {
	case "consume":
		if value.Token == "" || value.DeliveryID == "" || value.Repository == "" || value.Operation == "" || value.MutationHash == "" {
			service.respond(connection, response{Error: "authority_request_invalid"})
			return
		}
		capability, err := service.broker.ConsumeCapabilityForWorker(value.Token, service.workerID, value.DeliveryID, value.Repository, value.Operation, value.MutationHash, value.At)
		if err != nil {
			service.respond(connection, response{Error: "capability_rejected"})
			return
		}
		service.respond(connection, response{Capability: capability})
	case "finalize":
		if value.Token == "" || value.Outcome == "" {
			service.respond(connection, response{Error: "authority_request_invalid"})
			return
		}
		if err := service.broker.FinalizeCapability(value.Token, value.Outcome, value.ResourceID, value.Reason, value.At); err != nil {
			service.respond(connection, response{Error: "finalization_rejected"})
			return
		}
		service.respond(connection, response{})
	case "authorize_reconciliation":
		capability, err := service.broker.AuthorizeReconciliationForWorker(value.TenantID, value.RequestID, service.workerID, value.Repository, value.Operation, value.MutationHash)
		if err != nil {
			service.respond(connection, response{Error: "reconciliation_rejected"})
			return
		}
		service.respond(connection, response{Capability: capability})
	case "finalize_reconciliation":
		if err := service.broker.FinalizeReconciliationForWorker(value.TenantID, value.RequestID, service.workerID, value.Outcome, value.ResourceID, value.At); err != nil {
			service.respond(connection, response{Error: "reconciliation_finalization_rejected"})
			return
		}
		service.respond(connection, response{})
	default:
		service.respond(connection, response{Error: "authority_action_invalid"})
	}
}

func (service *Server) socketPermissionsValid() bool {
	info, err := os.Stat(service.path)
	if err != nil || info.Mode().Perm() != 0o660 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Gid) == service.socketGID
}

func (service *Server) respond(connection net.Conn, value response) {
	_ = json.NewEncoder(connection).Encode(value)
}
