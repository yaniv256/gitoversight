package notifications_test

import (
	"context"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/notifications"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

type hiveSender struct {
	agent string
	text  string
}

func (sender *hiveSender) Send(_ context.Context, agent, text string) error {
	sender.agent, sender.text = agent, text
	return nil
}

func TestHiveAdapterUsesNarrowDestinationContract(t *testing.T) {
	sender := &hiveSender{}
	adapter := notifications.NewHiveAdapter(sender)
	err := adapter.Deliver(context.Background(), notifications.Delivery{
		Event:       storage.OutboxEvent{ID: "event-1", Kind: "operation_approved", PayloadJSON: []byte(`{"operation_id":"op-1"}`)},
		Destination: []byte(`{"agent":"zara"}`),
	})
	if err != nil || sender.agent != "zara" || sender.text == "" {
		t.Fatalf("agent=%q text=%q err=%v", sender.agent, sender.text, err)
	}
	if err := adapter.Deliver(context.Background(), notifications.Delivery{Destination: []byte(`{"room":"private"}`)}); err == nil {
		t.Fatal("invalid Hive destination accepted")
	}
}
