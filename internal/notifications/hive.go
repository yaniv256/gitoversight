package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type HiveSender interface {
	Send(context.Context, string, string) error
}

type HiveAdapter struct{ sender HiveSender }

func NewHiveAdapter(sender HiveSender) *HiveAdapter { return &HiveAdapter{sender: sender} }

func (adapter *HiveAdapter) Deliver(ctx context.Context, delivery Delivery) error {
	if adapter == nil || adapter.sender == nil || delivery.Event.ID == "" {
		return errors.New("Hive adapter is unavailable")
	}
	var destination struct {
		Agent string `json:"agent"`
	}
	decoder := json.NewDecoder(bytes.NewReader(delivery.Destination))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&destination); err != nil || destination.Agent == "" || decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid Hive destination")
	}
	return adapter.sender.Send(ctx, destination.Agent, fmt.Sprintf("Git Oversight event %s (%s): %s", delivery.Event.ID, delivery.Event.Kind, string(delivery.Event.PayloadJSON)))
}
