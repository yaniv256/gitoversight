package contract_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yaniv256/gitoversight.dev/internal/httpapi"
)

type namedCheck struct {
	name string
	err  error
}

func (check namedCheck) Name() string                { return check.name }
func (check namedCheck) Check(context.Context) error { return check.err }

func TestReadinessReportsEveryFailedDependencyWithoutLeakingDetails(t *testing.T) {
	probe := httpapi.NewReadiness([]httpapi.Check{
		namedCheck{name: "sqlite"},
		namedCheck{name: "policy", err: errors.New("secret database path")},
		namedCheck{name: "worker", err: errors.New("token=secret")},
	})
	status := probe.Status(context.Background())
	if status.Ready || len(status.Failed) != 2 || status.Failed[0] != "policy" || status.Failed[1] != "worker" {
		t.Fatalf("unexpected readiness: %+v", status)
	}
}
