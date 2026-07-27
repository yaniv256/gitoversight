package notifications

import "github.com/yaniv256/gitoversight.dev/internal/storage"

type Delivery struct {
	Event       storage.OutboxEvent
	Destination []byte
}
