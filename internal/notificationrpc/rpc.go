package notificationrpc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/identity"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

const (
	maxMessageBytes = 1 << 20
	maxConnections  = 64
	requestTimeout  = 10 * time.Second
)

type request struct {
	Action        string                       `json:"action"`
	WorkerID      string                       `json:"worker_id,omitempty"`
	Now           time.Time                    `json:"now"`
	LeaseDuration time.Duration                `json:"lease_duration,omitempty"`
	Delivery      storage.NotificationDelivery `json:"delivery,omitempty"`
	NextAttemptAt time.Time                    `json:"next_attempt_at,omitempty"`
	LastError     string                       `json:"last_error,omitempty"`
	MaxAttempts   int                          `json:"max_attempts,omitempty"`
}

type response struct {
	Worked   bool                          `json:"worked,omitempty"`
	Delivery *storage.NotificationDelivery `json:"delivery,omitempty"`
	Error    string                        `json:"error,omitempty"`
}

type Client struct{ path string }

func NewClient(path string) *Client { return &Client{path: path} }

func (client *Client) ExpandNotificationOutbox(ctx context.Context, now time.Time) (bool, error) {
	result, err := client.call(ctx, request{Action: "expand", Now: now})
	return result.Worked, err
}

func (client *Client) ClaimNotificationDelivery(ctx context.Context, workerID string, now time.Time, lease time.Duration) (storage.NotificationDelivery, bool, error) {
	result, err := client.call(ctx, request{Action: "claim", WorkerID: workerID, Now: now, LeaseDuration: lease})
	if err != nil || result.Delivery == nil {
		return storage.NotificationDelivery{}, false, err
	}
	return *result.Delivery, result.Worked, nil
}

func (client *Client) CompleteNotificationDelivery(ctx context.Context, delivery storage.NotificationDelivery, now time.Time) error {
	_, err := client.call(ctx, request{Action: "complete", Delivery: delivery, Now: now})
	return err
}

func (client *Client) RetryNotificationDelivery(ctx context.Context, delivery storage.NotificationDelivery, next time.Time, lastError string, maxAttempts int) error {
	_, err := client.call(ctx, request{Action: "retry", Delivery: delivery, NextAttemptAt: next, LastError: lastError, MaxAttempts: maxAttempts, Now: time.Now().UTC()})
	return err
}

func (client *Client) call(ctx context.Context, value request) (response, error) {
	dialer := net.Dialer{Timeout: time.Second}
	connection, err := dialer.DialContext(ctx, "unix", client.path)
	if err != nil {
		return response{}, errors.New("notification authority unavailable")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(requestTimeout))
	requestErr := json.NewEncoder(connection).Encode(value)
	var result response
	decoder := json.NewDecoder(io.LimitReader(connection, maxMessageBytes))
	decoder.DisallowUnknownFields()
	responseErr := decoder.Decode(&result)
	if requestErr != nil {
		if responseErr == nil && result.Error != "" {
			return result, errors.New(result.Error)
		}
		return response{}, errors.New("notification authority request failed")
	}
	if responseErr != nil {
		return response{}, errors.New("notification authority response failed")
	}
	if result.Error != "" {
		return result, errors.New(result.Error)
	}
	return result, nil
}

type Server struct {
	path      string
	db        *sqlite.DB
	notifyUID uint32
	socketGID int
}

func NewServer(path string, db *sqlite.DB, notifyUID uint32, socketGID int) *Server {
	return &Server{path: path, db: db, notifyUID: notifyUID, socketGID: socketGID}
}

func (service *Server) Listen() (net.Listener, error) {
	if service.path == "" || service.db == nil || service.socketGID < 0 {
		return nil, errors.New("notification RPC configuration is incomplete")
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
	_ = connection.SetDeadline(time.Now().Add(requestTimeout))
	if !service.socketPermissionsValid() {
		service.respond(connection, response{Error: "notification_socket_permissions_invalid"})
		return
	}
	peer, err := identity.FromUnixConn(connection)
	if err != nil || peer.UID != service.notifyUID {
		service.respond(connection, response{Error: "notification_caller_forbidden"})
		return
	}
	var value request
	decoder := json.NewDecoder(io.LimitReader(connection, maxMessageBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		service.respond(connection, response{Error: "notification_request_invalid"})
		return
	}
	ctx := context.Background()
	switch value.Action {
	case "expand":
		worked, err := service.db.ExpandNotificationOutbox(ctx, value.Now)
		service.reply(connection, response{Worked: worked}, err)
	case "claim":
		delivery, worked, err := service.db.ClaimNotificationDelivery(ctx, value.WorkerID, value.Now, value.LeaseDuration)
		result := response{Worked: worked}
		if worked {
			result.Delivery = &delivery
		}
		service.reply(connection, result, err)
	case "complete":
		service.reply(connection, response{}, service.db.CompleteNotificationDelivery(ctx, value.Delivery, value.Now))
	case "retry":
		service.reply(connection, response{}, service.db.RetryNotificationDelivery(ctx, value.Delivery, value.NextAttemptAt, value.LastError, value.MaxAttempts))
	default:
		service.respond(connection, response{Error: "notification_action_invalid"})
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

func (service *Server) reply(connection net.Conn, value response, err error) {
	if err != nil {
		value.Error = "notification_operation_rejected"
	}
	service.respond(connection, value)
}

func (service *Server) respond(connection net.Conn, value response) {
	_ = json.NewEncoder(connection).Encode(value)
}
