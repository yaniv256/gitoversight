package notifications_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/notifications"
	"github.com/yaniv256/gitoversight.dev/internal/storage"
	"github.com/yaniv256/gitoversight.dev/internal/storage/sqlite"
)

type recordingAdapter struct {
	calls int
	fail  bool
}

func (adapter *recordingAdapter) Deliver(_ context.Context, delivery notifications.Delivery) error {
	adapter.calls++
	if delivery.Event.ID == "" || len(delivery.Destination) == 0 {
		return errors.New("incomplete delivery")
	}
	if adapter.fail {
		return errors.New("adapter unavailable")
	}
	return nil
}

func TestOutboxDeliveryIsOptionalRetryBoundedAndTenantScoped(t *testing.T) {
	ctx := context.Background()
	db := notificationDB(t)
	now := time.Unix(1_720_000_000, 0).UTC()
	seedNotificationAgent(t, db, "tenant-a", "zara", now)
	seedNotificationAgent(t, db, "tenant-b", "zara", now)

	if err := db.CreateNotificationSubscription(ctx, storage.NotificationSubscription{
		TenantID: "tenant-a", ID: "sub-1", AgentID: "zara", Adapter: "hive",
		EventTypes: []string{"operation_submitted"}, DestinationJSON: []byte(`{"agent":"zara"}`), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	appendNotificationEvent(t, db, "tenant-a", "event-1", now)
	appendNotificationEvent(t, db, "tenant-b", "event-2", now)

	adapter := &recordingAdapter{fail: true}
	dispatcher := notifications.NewDispatcher(db, map[string]notifications.Adapter{"hive": adapter}, notifications.Config{
		LeaseDuration: time.Minute, RetryDelay: time.Second, MaxAttempts: 2, Now: func() time.Time { return now },
	})
	if worked, err := dispatcher.RunOnce(ctx, "notify-1"); err != nil || !worked {
		t.Fatalf("first run worked=%v err=%v", worked, err)
	}
	now = now.Add(2 * time.Second)
	if worked, err := dispatcher.RunOnce(ctx, "notify-1"); err != nil || !worked {
		t.Fatalf("second run worked=%v err=%v", worked, err)
	}
	statuses, err := db.NotificationStatus(ctx, "tenant-a", "zara", "event-1")
	if err != nil || len(statuses) != 1 || statuses[0].State != "dead_letter" || statuses[0].AttemptCount != 2 {
		t.Fatalf("statuses=%+v err=%v", statuses, err)
	}
	if foreign, err := db.NotificationStatus(ctx, "tenant-b", "zara", "event-1"); err != nil || len(foreign) != 0 {
		t.Fatalf("cross-tenant statuses=%+v err=%v", foreign, err)
	}
	if adapter.calls != 2 {
		t.Fatalf("adapter calls=%d", adapter.calls)
	}

	// Tenant B has no subscription. Its event is consumed without invoking an adapter,
	// proving notifications are optional rather than an authority dependency.
	if worked, err := dispatcher.RunOnce(ctx, "notify-1"); err != nil || !worked {
		t.Fatalf("optional run worked=%v err=%v", worked, err)
	}
	if adapter.calls != 2 {
		t.Fatalf("adapter called for unsubscribed tenant: %d", adapter.calls)
	}
}

func TestSuccessfulDeliveryIsAcknowledgedOnce(t *testing.T) {
	ctx := context.Background()
	db := notificationDB(t)
	now := time.Unix(1_720_000_000, 0).UTC()
	seedNotificationAgent(t, db, "tenant-a", "zara", now)
	if err := db.CreateNotificationSubscription(ctx, storage.NotificationSubscription{
		TenantID: "tenant-a", ID: "sub-1", AgentID: "zara", Adapter: "hive",
		EventTypes: []string{"operation_submitted"}, DestinationJSON: []byte(`{"agent":"zara"}`), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	appendNotificationEvent(t, db, "tenant-a", "event-1", now)
	adapter := &recordingAdapter{}
	dispatcher := notifications.NewDispatcher(db, map[string]notifications.Adapter{"hive": adapter}, notifications.Config{Now: func() time.Time { return now }})
	if worked, err := dispatcher.RunOnce(ctx, "notify-1"); err != nil || !worked {
		t.Fatalf("worked=%v err=%v", worked, err)
	}
	statuses, err := db.NotificationStatus(ctx, "tenant-a", "zara", "event-1")
	if err != nil || len(statuses) != 1 || statuses[0].State != "delivered" || statuses[0].DeliveredAt == nil || adapter.calls != 1 {
		t.Fatalf("statuses=%+v calls=%d err=%v", statuses, adapter.calls, err)
	}
	if worked, err := dispatcher.RunOnce(ctx, "notify-1"); err != nil || worked {
		t.Fatalf("second worked=%v err=%v", worked, err)
	}
}

func TestWildcardSubscriptionCannotCrossAgentAudience(t *testing.T) {
	ctx := context.Background()
	db := notificationDB(t)
	now := time.Unix(1_720_000_000, 0).UTC()
	seedNotificationAgent(t, db, "tenant-a", "zara", now)
	seedNotificationAgent(t, db, "tenant-a", "tomas", now)
	for _, agentID := range []string{"zara", "tomas"} {
		if err := db.CreateNotificationSubscription(ctx, storage.NotificationSubscription{
			TenantID: "tenant-a", ID: "sub-" + agentID, AgentID: agentID, Adapter: "hive",
			EventTypes: []string{"*"}, DestinationJSON: []byte(`{"agent":"` + agentID + `"}`), CreatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	appendNotificationEvent(t, db, "tenant-a", "event-private-zara", now)
	if expanded, err := db.ExpandNotificationOutbox(ctx, now); err != nil || !expanded {
		t.Fatalf("expand=%v err=%v", expanded, err)
	}
	if statuses, err := db.NotificationStatus(ctx, "tenant-a", "zara", "event-private-zara"); err != nil || len(statuses) != 1 {
		t.Fatalf("owner statuses=%+v err=%v", statuses, err)
	}
	if statuses, err := db.NotificationStatus(ctx, "tenant-a", "tomas", "event-private-zara"); err != nil || len(statuses) != 0 {
		t.Fatalf("cross-agent statuses=%+v err=%v", statuses, err)
	}
}

func TestExpiredLeaseRecordsDuplicateRiskAndRevocationStopsDelivery(t *testing.T) {
	ctx := context.Background()
	db := notificationDB(t)
	now := time.Unix(1_720_000_000, 0).UTC()
	seedNotificationAgent(t, db, "tenant-a", "zara", now)
	if err := db.CreateNotificationSubscription(ctx, storage.NotificationSubscription{
		TenantID: "tenant-a", ID: "sub-1", AgentID: "zara", Adapter: "hive",
		EventTypes: []string{"operation_submitted"}, DestinationJSON: []byte(`{"agent":"zara"}`), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	appendNotificationEvent(t, db, "tenant-a", "event-1", now)
	if expanded, err := db.ExpandNotificationOutbox(ctx, now); err != nil || !expanded {
		t.Fatalf("expand=%v err=%v", expanded, err)
	}
	first, ok, err := db.ClaimNotificationDelivery(ctx, "notify-crashed", now, time.Second)
	if err != nil || !ok || first.DuplicateRisk {
		t.Fatalf("first claim=%+v ok=%v err=%v", first, ok, err)
	}
	now = now.Add(2 * time.Second)
	second, ok, err := db.ClaimNotificationDelivery(ctx, "notify-recovered", now, time.Second)
	if err != nil || !ok || !second.DuplicateRisk || second.AttemptCount != 2 {
		t.Fatalf("second claim=%+v ok=%v err=%v", second, ok, err)
	}
	if err := db.RetryNotificationDelivery(ctx, second, now.Add(time.Second), "uncertain acknowledgement", 2); err != nil {
		t.Fatal(err)
	}

	appendNotificationEvent(t, db, "tenant-a", "event-2", now)
	if err := db.RevokeNotificationSubscription(ctx, "tenant-a", "zara", "sub-1", now); err != nil {
		t.Fatal(err)
	}
	if expanded, err := db.ExpandNotificationOutbox(ctx, now); err != nil || !expanded {
		t.Fatalf("expand revoked=%v err=%v", expanded, err)
	}
	statuses, err := db.NotificationStatus(ctx, "tenant-a", "zara", "event-2")
	if err != nil || len(statuses) != 0 {
		t.Fatalf("revoked statuses=%+v err=%v", statuses, err)
	}
}

func TestConcurrentNotificationClaimHasOneWinner(t *testing.T) {
	ctx := context.Background()
	db := notificationDB(t)
	now := time.Unix(1_720_000_000, 0).UTC()
	seedNotificationAgent(t, db, "tenant-a", "zara", now)
	if err := db.CreateNotificationSubscription(ctx, storage.NotificationSubscription{
		TenantID: "tenant-a", ID: "sub-1", AgentID: "zara", Adapter: "hive",
		EventTypes: []string{"operation_submitted"}, DestinationJSON: []byte(`{"agent":"zara"}`), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	appendNotificationEvent(t, db, "tenant-a", "event-1", now)
	if _, err := db.ExpandNotificationOutbox(ctx, now); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan bool, 2)
	errorsSeen := make(chan error, 2)
	var wait sync.WaitGroup
	for _, workerID := range []string{"worker-a", "worker-b"} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, ok, err := db.ClaimNotificationDelivery(ctx, workerID, now, time.Minute)
			results <- ok
			errorsSeen <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsSeen)
	winners := 0
	for ok := range results {
		if ok {
			winners++
		}
	}
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("claim error=%v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("winners=%d", winners)
	}
}

func notificationDB(t *testing.T) *sqlite.DB {
	t.Helper()
	db, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(t.TempDir(), "gitoversight.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seedNotificationAgent(t *testing.T, db *sqlite.DB, tenantID, agentID string, now time.Time) {
	t.Helper()
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		if err := tx.EnsureTenant(context.Background(), tenantID, now); err != nil {
			return err
		}
		return tx.EnsureAgent(context.Background(), tenantID, agentID, now)
	}); err != nil {
		t.Fatal(err)
	}
}

func appendNotificationEvent(t *testing.T, db *sqlite.DB, tenantID, id string, now time.Time) {
	t.Helper()
	if err := db.WithTx(context.Background(), func(tx *sqlite.Tx) error {
		return tx.AppendOutbox(context.Background(), storage.OutboxEvent{
			TenantID: tenantID, ID: id, Kind: "operation_submitted", AudienceAgentID: "zara", PayloadJSON: []byte(`{"operation_id":"op-1"}`), State: "pending", CreatedAt: now,
		})
	}); err != nil {
		t.Fatal(err)
	}
}
