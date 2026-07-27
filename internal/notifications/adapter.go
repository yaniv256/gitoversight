package notifications

import "context"

type Adapter interface {
	Deliver(context.Context, Delivery) error
}
