package notifications

import (
	"context"
	"errors"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

type Store interface {
	ExpandNotificationOutbox(context.Context, time.Time) (bool, error)
	ClaimNotificationDelivery(context.Context, string, time.Time, time.Duration) (storage.NotificationDelivery, bool, error)
	CompleteNotificationDelivery(context.Context, storage.NotificationDelivery, time.Time) error
	RetryNotificationDelivery(context.Context, storage.NotificationDelivery, time.Time, string, int) error
}

type Config struct {
	LeaseDuration time.Duration
	RetryDelay    time.Duration
	MaxAttempts   int
	Now           func() time.Time
}

type Dispatcher struct {
	store    Store
	adapters map[string]Adapter
	config   Config
}

func NewDispatcher(store Store, adapters map[string]Adapter, config Config) *Dispatcher {
	if config.LeaseDuration <= 0 {
		config.LeaseDuration = time.Minute
	}
	if config.RetryDelay <= 0 {
		config.RetryDelay = 10 * time.Second
	}
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = 5
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Dispatcher{store: store, adapters: adapters, config: config}
}

func (dispatcher *Dispatcher) RunOnce(ctx context.Context, workerID string) (bool, error) {
	if dispatcher == nil || dispatcher.store == nil || workerID == "" {
		return false, errors.New("notification dispatcher is unavailable")
	}
	now := dispatcher.config.Now().UTC()
	delivery, ok, err := dispatcher.store.ClaimNotificationDelivery(ctx, workerID, now, dispatcher.config.LeaseDuration)
	if err != nil {
		return false, err
	}
	if !ok {
		expanded, err := dispatcher.store.ExpandNotificationOutbox(ctx, now)
		if err != nil || !expanded {
			return expanded, err
		}
		delivery, ok, err = dispatcher.store.ClaimNotificationDelivery(ctx, workerID, now, dispatcher.config.LeaseDuration)
		if err != nil {
			return true, err
		}
		if !ok {
			return true, nil
		}
	}
	adapter := dispatcher.adapters[delivery.Adapter]
	if adapter == nil {
		err = errors.New("notification adapter is not configured")
	} else {
		err = adapter.Deliver(ctx, Delivery{Event: delivery.Event, Destination: delivery.DestinationJSON})
	}
	if err == nil {
		return true, dispatcher.store.CompleteNotificationDelivery(ctx, delivery, dispatcher.config.Now().UTC())
	}
	if persistErr := dispatcher.store.RetryNotificationDelivery(ctx, delivery, dispatcher.config.Now().UTC().Add(dispatcher.config.RetryDelay), "delivery failed", dispatcher.config.MaxAttempts); persistErr != nil {
		return true, persistErr
	}
	return true, nil
}
