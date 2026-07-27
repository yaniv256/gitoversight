package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/notificationrpc"
	"github.com/yaniv256/gitoversight.dev/internal/notifications"
)

type config struct {
	AuthoritySocket string `json:"authority_socket"`
	WorkerID        string `json:"worker_id"`
	PollInterval    string `json:"poll_interval"`
	LeaseDuration   string `json:"lease_duration"`
	RetryDelay      string `json:"retry_delay"`
	MaxAttempts     int    `json:"max_attempts"`
	HiveEndpoint    string `json:"hive_endpoint,omitempty"`
	HiveTokenFile   string `json:"hive_token_file,omitempty"`
	RequestTimeout  string `json:"request_timeout,omitempty"`
}

type hiveHTTPSender struct {
	endpoint string
	token    string
	client   *http.Client
}

func (sender *hiveHTTPSender) Send(ctx context.Context, agent, message string) error {
	payload, err := json.Marshal(map[string]string{"agent": agent, "message": message})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, sender.endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+sender.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := sender.client.Do(request)
	if err != nil {
		return errors.New("notification provider unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("notification provider rejected delivery")
	}
	return nil
}

func main() {
	configPath := flag.String("config", "", "path to notification worker configuration")
	flag.Parse()
	if *configPath == "" {
		fatal("-config is required")
	}
	payload, err := os.ReadFile(*configPath)
	if err != nil {
		fatal("read config: %v", err)
	}
	var cfg config
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		fatal("decode config: %v", err)
	}
	if cfg.AuthoritySocket == "" || cfg.WorkerID == "" || cfg.MaxAttempts <= 0 {
		fatal("notification configuration is incomplete")
	}
	pollInterval := parseDuration(cfg.PollInterval, "poll_interval")
	leaseDuration := parseDuration(cfg.LeaseDuration, "lease_duration")
	retryDelay := parseDuration(cfg.RetryDelay, "retry_delay")
	requestTimeout := 10 * time.Second
	if cfg.RequestTimeout != "" {
		requestTimeout = parseDuration(cfg.RequestTimeout, "request_timeout")
	}

	adapters := map[string]notifications.Adapter{}
	if cfg.HiveEndpoint != "" || cfg.HiveTokenFile != "" {
		parsed, parseErr := url.Parse(cfg.HiveEndpoint)
		if parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" || cfg.HiveTokenFile == "" {
			fatal("Hive adapter requires an HTTPS endpoint and token credential")
		}
		token, readErr := os.ReadFile(cfg.HiveTokenFile)
		if readErr != nil || strings.TrimSpace(string(token)) == "" {
			fatal("read Hive token credential")
		}
		adapters["hive"] = notifications.NewHiveAdapter(&hiveHTTPSender{
			endpoint: parsed.String(), token: strings.TrimSpace(string(token)), client: &http.Client{Timeout: requestTimeout},
		})
	}
	dispatcher := notifications.NewDispatcher(notificationrpc.NewClient(cfg.AuthoritySocket), adapters, notifications.Config{
		LeaseDuration: leaseDuration, RetryDelay: retryDelay, MaxAttempts: cfg.MaxAttempts,
	})
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	for ctx.Err() == nil {
		worked, err := dispatcher.RunOnce(ctx, cfg.WorkerID)
		if err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "notification cycle failed")
		}
		if worked {
			continue
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func parseDuration(raw, name string) time.Duration {
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		fatal("%s must be a positive duration", name)
	}
	return value
}

func fatal(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
