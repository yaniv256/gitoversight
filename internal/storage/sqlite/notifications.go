package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/yaniv256/gitoversight.dev/internal/storage"
)

func (db *DB) CreateNotificationSubscription(ctx context.Context, subscription storage.NotificationSubscription) error {
	if subscription.TenantID == "" || subscription.ID == "" || subscription.AgentID == "" || subscription.Adapter == "" || len(subscription.EventTypes) == 0 || len(subscription.DestinationJSON) == 0 || subscription.CreatedAt.IsZero() || !json.Valid(subscription.DestinationJSON) {
		return errors.New("notification subscription is incomplete")
	}
	events, err := json.Marshal(subscription.EventTypes)
	if err != nil {
		return err
	}
	_, err = db.sql.ExecContext(ctx, `INSERT INTO notification_subscriptions (tenant_id, id, agent_id, adapter, destination_json, event_types_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`, subscription.TenantID, subscription.ID, subscription.AgentID, subscription.Adapter, subscription.DestinationJSON, events, unix(subscription.CreatedAt))
	return err
}

func (db *DB) RevokeNotificationSubscription(ctx context.Context, tenantID, agentID, subscriptionID string, revokedAt time.Time) error {
	if tenantID == "" || agentID == "" || subscriptionID == "" || revokedAt.IsZero() {
		return errors.New("notification revocation is incomplete")
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE notification_subscriptions SET revoked_at = ? WHERE tenant_id = ? AND id = ? AND agent_id = ? AND revoked_at IS NULL`, unix(revokedAt), tenantID, subscriptionID, agentID)
	if err != nil {
		return err
	}
	if err := requireOneRow(result, "notification subscription"); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT outbox_id FROM notification_deliveries WHERE tenant_id = ? AND subscription_id = ? AND state IN ('pending', 'leased')`, tenantID, subscriptionID)
	if err != nil {
		return err
	}
	var outboxIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		outboxIDs = append(outboxIDs, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE notification_deliveries SET state = 'dead_letter', last_error = 'subscription revoked', lease_owner = NULL, lease_token = NULL, lease_until = NULL WHERE tenant_id = ? AND subscription_id = ? AND state IN ('pending', 'leased')`, tenantID, subscriptionID)
	if err != nil {
		return err
	}
	for _, outboxID := range outboxIDs {
		if err := refreshOutboxState(ctx, tx, tenantID, outboxID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) NotificationSubscriptions(ctx context.Context, tenantID, agentID string) ([]storage.NotificationSubscription, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id, adapter, event_types_json, destination_json, created_at, revoked_at FROM notification_subscriptions WHERE tenant_id = ? AND agent_id = ? ORDER BY created_at, id`, tenantID, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var subscriptions []storage.NotificationSubscription
	for rows.Next() {
		var item storage.NotificationSubscription
		var eventJSON []byte
		var created int64
		var revoked sql.NullInt64
		item.TenantID, item.AgentID = tenantID, agentID
		if err := rows.Scan(&item.ID, &item.Adapter, &eventJSON, &item.DestinationJSON, &created, &revoked); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(eventJSON, &item.EventTypes); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(created, 0).UTC()
		if revoked.Valid {
			value := time.Unix(revoked.Int64, 0).UTC()
			item.RevokedAt = &value
		}
		subscriptions = append(subscriptions, item)
	}
	return subscriptions, rows.Err()
}

func (db *DB) ExpandNotificationOutbox(ctx context.Context, now time.Time) (bool, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var event storage.OutboxEvent
	var created int64
	err = tx.QueryRowContext(ctx, `SELECT tenant_id, id, event_type, audience_agent_id, payload_json, state, created_at FROM outbox_deliveries WHERE state = 'pending' ORDER BY created_at, tenant_id, id LIMIT 1`).Scan(&event.TenantID, &event.ID, &event.Kind, &event.AudienceAgentID, &event.PayloadJSON, &event.State, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	event.CreatedAt = time.Unix(created, 0).UTC()
	result, err := tx.ExecContext(ctx, `UPDATE outbox_deliveries SET state = 'expanding' WHERE tenant_id = ? AND id = ? AND state = 'pending'`, event.TenantID, event.ID)
	if err != nil {
		return false, err
	}
	if err := requireOneRow(result, "outbox event"); err != nil {
		return false, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, agent_id, adapter, destination_json, event_types_json FROM notification_subscriptions WHERE tenant_id = ? AND agent_id = ? AND revoked_at IS NULL`, event.TenantID, event.AudienceAgentID)
	if err != nil {
		return false, err
	}
	type target struct {
		id, agent, adapter  string
		destination, events []byte
	}
	var targets []target
	for rows.Next() {
		var item target
		if err := rows.Scan(&item.id, &item.agent, &item.adapter, &item.destination, &item.events); err != nil {
			rows.Close()
			return false, err
		}
		targets = append(targets, item)
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	count := 0
	for _, target := range targets {
		var eventTypes []string
		if err := json.Unmarshal(target.events, &eventTypes); err != nil {
			return false, err
		}
		if !containsEvent(eventTypes, event.Kind) {
			continue
		}
		id := event.ID + ":" + target.id
		if _, err := tx.ExecContext(ctx, `INSERT INTO notification_deliveries (tenant_id, id, outbox_id, subscription_id, agent_id, adapter, destination_json, state, available_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`, event.TenantID, id, event.ID, target.id, target.agent, target.adapter, target.destination, unix(now), unix(now)); err != nil {
			return false, err
		}
		count++
	}
	state := "expanded"
	if count == 0 {
		state = "delivered"
	}
	if _, err := tx.ExecContext(ctx, `UPDATE outbox_deliveries SET state = ? WHERE tenant_id = ? AND id = ?`, state, event.TenantID, event.ID); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (db *DB) ClaimNotificationDelivery(ctx context.Context, workerID string, now time.Time, leaseDuration time.Duration) (storage.NotificationDelivery, bool, error) {
	if workerID == "" || now.IsZero() || leaseDuration <= 0 {
		return storage.NotificationDelivery{}, false, errors.New("notification claim is incomplete")
	}
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return storage.NotificationDelivery{}, false, err
	}
	token := hex.EncodeToString(tokenBytes)
	var tenantID, id string
	err := db.sql.QueryRowContext(ctx, `UPDATE notification_deliveries
SET state = 'leased', attempt_count = attempt_count + 1, lease_owner = ?, lease_token = ?, lease_until = ?,
    duplicate_risk = CASE WHEN state = 'leased' OR duplicate_risk = 1 THEN 1 ELSE 0 END
WHERE (tenant_id, id) = (
    SELECT tenant_id, id FROM notification_deliveries
    WHERE (state = 'pending' AND available_at <= ?) OR (state = 'leased' AND lease_until <= ?)
    ORDER BY created_at, tenant_id, id LIMIT 1
)
AND ((state = 'pending' AND available_at <= ?) OR (state = 'leased' AND lease_until <= ?))
RETURNING tenant_id, id`, workerID, token, unix(now.Add(leaseDuration)), unix(now), unix(now), unix(now), unix(now)).Scan(&tenantID, &id)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.NotificationDelivery{}, false, nil
	}
	if err != nil {
		return storage.NotificationDelivery{}, false, err
	}
	delivery, err := scanNotificationDelivery(db.sql.QueryRowContext(ctx, `SELECT d.tenant_id, d.id, d.outbox_id, d.subscription_id, d.agent_id, d.adapter, d.destination_json, d.state, d.attempt_count, d.available_at, d.lease_token, d.lease_until, d.duplicate_risk, d.last_error, d.created_at, d.delivered_at, o.event_type, o.payload_json, o.created_at FROM notification_deliveries d JOIN outbox_deliveries o ON o.tenant_id = d.tenant_id AND o.id = d.outbox_id WHERE d.tenant_id = ? AND d.id = ? AND d.lease_token = ?`, tenantID, id, token))
	if err != nil {
		return storage.NotificationDelivery{}, false, err
	}
	return delivery, true, nil
}

func (db *DB) CompleteNotificationDelivery(ctx context.Context, delivery storage.NotificationDelivery, deliveredAt time.Time) error {
	return db.finishNotificationDelivery(ctx, delivery, deliveredAt, "", 0, true)
}

func (db *DB) RetryNotificationDelivery(ctx context.Context, delivery storage.NotificationDelivery, availableAt time.Time, detail string, maxAttempts int) error {
	return db.finishNotificationDelivery(ctx, delivery, availableAt, detail, maxAttempts, false)
}

func (db *DB) finishNotificationDelivery(ctx context.Context, delivery storage.NotificationDelivery, at time.Time, detail string, maxAttempts int, delivered bool) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var result sql.Result
	if delivered {
		result, err = tx.ExecContext(ctx, `UPDATE notification_deliveries SET state = 'delivered', delivered_at = ?, lease_owner = NULL, lease_token = NULL, lease_until = NULL WHERE tenant_id = ? AND id = ? AND state = 'leased' AND lease_token = ?`, unix(at), delivery.TenantID, delivery.ID, delivery.LeaseToken)
	} else {
		state := "pending"
		if maxAttempts <= 0 || delivery.AttemptCount >= maxAttempts {
			state = "dead_letter"
		}
		result, err = tx.ExecContext(ctx, `UPDATE notification_deliveries SET state = ?, available_at = ?, last_error = ?, lease_owner = NULL, lease_token = NULL, lease_until = NULL WHERE tenant_id = ? AND id = ? AND state = 'leased' AND lease_token = ?`, state, unix(at), safeNotificationError(detail), delivery.TenantID, delivery.ID, delivery.LeaseToken)
	}
	if err != nil {
		return err
	}
	if err := requireOneRow(result, "notification delivery"); err != nil {
		return err
	}
	if err := refreshOutboxState(ctx, tx, delivery.TenantID, delivery.OutboxID); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) NotificationStatus(ctx context.Context, tenantID, agentID, outboxID string) ([]storage.NotificationDelivery, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT d.tenant_id, d.id, d.outbox_id, d.subscription_id, d.agent_id, d.adapter, d.destination_json, d.state, d.attempt_count, d.available_at, d.lease_token, d.lease_until, d.duplicate_risk, d.last_error, d.created_at, d.delivered_at, o.event_type, o.payload_json, o.created_at FROM notification_deliveries d JOIN outbox_deliveries o ON o.tenant_id = d.tenant_id AND o.id = d.outbox_id WHERE d.tenant_id = ? AND d.agent_id = ? AND d.outbox_id = ? ORDER BY d.id`, tenantID, agentID, outboxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var deliveries []storage.NotificationDelivery
	for rows.Next() {
		item, err := scanNotificationDelivery(rows)
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, item)
	}
	return deliveries, rows.Err()
}

type rowScanner interface{ Scan(...any) error }

func scanNotificationDelivery(row rowScanner) (storage.NotificationDelivery, error) {
	var item storage.NotificationDelivery
	var available, leaseUntil, created, deliveredAt, eventCreated sql.NullInt64
	var leaseToken, lastError sql.NullString
	var duplicate int
	err := row.Scan(&item.TenantID, &item.ID, &item.OutboxID, &item.SubscriptionID, &item.AgentID, &item.Adapter, &item.DestinationJSON, &item.State, &item.AttemptCount, &available, &leaseToken, &leaseUntil, &duplicate, &lastError, &created, &deliveredAt, &item.Event.Kind, &item.Event.PayloadJSON, &eventCreated)
	if err != nil {
		return item, err
	}
	item.Event.TenantID, item.Event.ID = item.TenantID, item.OutboxID
	item.AvailableAt, item.CreatedAt, item.Event.CreatedAt = unixTime(available), unixTime(created), unixTime(eventCreated)
	item.LeaseToken, item.LeaseUntil, item.DuplicateRisk, item.LastError = leaseToken.String, unixTime(leaseUntil), duplicate == 1, lastError.String
	if deliveredAt.Valid {
		value := unixTime(deliveredAt)
		item.DeliveredAt = &value
	}
	return item, nil
}

func refreshOutboxState(ctx context.Context, tx *sql.Tx, tenantID, outboxID string) error {
	var active, dead int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM notification_deliveries WHERE tenant_id = ? AND outbox_id = ? AND state IN ('pending', 'leased')`, tenantID, outboxID).Scan(&active); err != nil {
		return err
	}
	if active > 0 {
		return nil
	}
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM notification_deliveries WHERE tenant_id = ? AND outbox_id = ? AND state = 'dead_letter'`, tenantID, outboxID).Scan(&dead); err != nil {
		return err
	}
	state := "delivered"
	if dead > 0 {
		state = "dead_letter"
	}
	_, err := tx.ExecContext(ctx, `UPDATE outbox_deliveries SET state = ? WHERE tenant_id = ? AND id = ?`, state, tenantID, outboxID)
	return err
}

func containsEvent(events []string, value string) bool {
	for _, event := range events {
		if event == value || event == "*" {
			return true
		}
	}
	return false
}

func safeNotificationError(string) string { return "delivery failed" }

func unixTime(value sql.NullInt64) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return time.Unix(value.Int64, 0).UTC()
}
