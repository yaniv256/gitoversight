package agentauth

import (
	"testing"
	"time"
)

func TestFixedWindowLimiterRejectsExcessAndResets(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	limiter, err := NewFixedWindowLimiter(2, time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if !limiter.Allow("192.0.2.1") || !limiter.Allow("192.0.2.1") {
		t.Fatal("allowed requests were rejected")
	}
	if limiter.Allow("192.0.2.1") {
		t.Fatal("excess request was allowed")
	}
	if !limiter.Allow("198.51.100.2") {
		t.Fatal("one source exhausted another source's allowance")
	}
	now = now.Add(time.Minute)
	if !limiter.Allow("192.0.2.1") {
		t.Fatal("window did not reset")
	}
}
