package events

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/smallstep/certificates/db"
)

type receivedEvent struct {
	id        string
	eventType string
	payload   Payload
}

// receiver is a test webhook receiver that records every delivery.
type receiver struct {
	mu        sync.Mutex
	received  []receivedEvent
	failTimes int
	always500 bool
}

func (r *receiver) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.always500 || r.failTimes > 0 {
			r.failTimes--
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var p Payload
		if err := json.NewDecoder(req.Body).Decode(&p); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.received = append(r.received, receivedEvent{
			id:        req.Header.Get("X-Step-Event-Id"),
			eventType: req.Header.Get("X-Step-Event-Type"),
			payload:   p,
		})
		w.WriteHeader(http.StatusOK)
	})
}

func (r *receiver) events() []receivedEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]receivedEvent, len(r.received))
	copy(out, r.received)
	return out
}

func testOptions(url string, store Store) Options {
	return Options{
		Webhooks: []Webhook{{URL: url}},
		Store:    store,
		Retry: RetryOptions{
			MaxAttempts:    3,
			InitialBackoff: 5 * time.Millisecond,
			MaxBackoff:     20 * time.Millisecond,
			Multiplier:     2,
		},
		RateLimit:    1000,
		PollInterval: 10 * time.Millisecond,
	}
}

func testEvent(t *testing.T, eventType string) *Event {
	t.Helper()
	return &Event{
		Payload: &Payload{
			EventID:     "test-event-" + eventType,
			EventType:   eventType,
			Timestamp:   time.Now().UTC(),
			Fingerprint: "fingerprint-" + eventType,
		},
		SerialNumber: "123",
	}
}

// waitFor polls cond until it returns true or the timeout elapses.
func waitFor(t *testing.T, timeout time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", msg)
}

func TestDispatcher_Deliver(t *testing.T) {
	rcv := &receiver{}
	srv := httptest.NewServer(rcv.handler())
	defer srv.Close()

	store := NewMemoryStore()
	d := NewDispatcher(testOptions(srv.URL, store))
	defer d.Stop()

	ev := testEvent(t, TypeX509Signed)
	if err := d.Notify(ev); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 5*time.Second, "event to be delivered", func() bool {
		return len(rcv.events()) == 1
	})

	got := rcv.events()[0]
	if got.id != ev.Payload.EventID {
		t.Errorf("expected event id %q, got %q", ev.Payload.EventID, got.id)
	}
	if got.eventType != TypeX509Signed {
		t.Errorf("expected event type %q, got %q", TypeX509Signed, got.eventType)
	}
	if got.payload.Fingerprint != "fingerprint-x509.signed" {
		t.Errorf("expected fingerprint in payload, got %q", got.payload.Fingerprint)
	}

	waitFor(t, 5*time.Second, "record to be marked delivered", func() bool {
		rec, err := store.GetEvent(ev.Payload.EventID)
		return err == nil && rec.Status == db.EventStatusDelivered
	})
	rec, err := store.GetEvent(ev.Payload.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", rec.Attempts)
	}
	if rec.DeliveredAt == nil {
		t.Error("expected DeliveredAt to be set")
	}
	if rec.Fingerprint != "fingerprint-x509.signed" {
		t.Errorf("expected denormalized fingerprint on record, got %q", rec.Fingerprint)
	}
}

func TestDispatcher_RetryThenDeliver_Idempotent(t *testing.T) {
	rcv := &receiver{failTimes: 2}
	srv := httptest.NewServer(rcv.handler())
	defer srv.Close()

	store := NewMemoryStore()
	d := NewDispatcher(testOptions(srv.URL, store))
	defer d.Stop()

	ev := testEvent(t, TypeX509Renewed)
	if err := d.Notify(ev); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 5*time.Second, "event to be delivered after retries", func() bool {
		return len(rcv.events()) == 1
	})

	if got := rcv.events()[0].id; got != ev.Payload.EventID {
		t.Errorf("expected stable event id %q across retries, got %q", ev.Payload.EventID, got)
	}

	waitFor(t, 5*time.Second, "record to be marked delivered", func() bool {
		rec, err := store.GetEvent(ev.Payload.EventID)
		return err == nil && rec.Status == db.EventStatusDelivered
	})
	rec, err := store.GetEvent(ev.Payload.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", rec.Attempts)
	}
}

func TestDispatcher_TerminalFailure(t *testing.T) {
	rcv := &receiver{always500: true}
	srv := httptest.NewServer(rcv.handler())
	defer srv.Close()

	store := NewMemoryStore()
	d := NewDispatcher(testOptions(srv.URL, store))
	defer d.Stop()

	ev := testEvent(t, TypeX509Signed)
	if err := d.Notify(ev); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 5*time.Second, "event to be marked failed", func() bool {
		rec, err := store.GetEvent(ev.Payload.EventID)
		return err == nil && rec.Status == db.EventStatusFailed
	})

	rec, err := store.GetEvent(ev.Payload.EventID)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", rec.Attempts)
	}
	if rec.LastError == "" {
		t.Error("expected LastError to be set")
	}

	stats, err := d.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Failed != 1 || stats.Total != 1 || stats.Pending != 0 || stats.Delivered != 0 {
		t.Errorf("unexpected stats: %+v", stats)
	}

	failed, err := d.List(db.EventStatusFailed, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(failed) != 1 || failed[0].ID != ev.Payload.EventID {
		t.Errorf("expected the failed event to be queryable, got %+v", failed)
	}
}

func TestDispatcher_TypeFilter(t *testing.T) {
	allRcv := &receiver{}
	allSrv := httptest.NewServer(allRcv.handler())
	defer allSrv.Close()

	renewRcv := &receiver{}
	renewSrv := httptest.NewServer(renewRcv.handler())
	defer renewSrv.Close()

	store := NewMemoryStore()
	opts := testOptions(allSrv.URL, store)
	opts.Webhooks = []Webhook{
		{URL: allSrv.URL},
		{URL: renewSrv.URL, Events: []string{TypeX509Renewed}},
	}
	d := NewDispatcher(opts)
	defer d.Stop()

	if err := d.Notify(testEvent(t, TypeX509Signed)); err != nil {
		t.Fatal(err)
	}
	renewEv := testEvent(t, TypeX509Renewed)
	if err := d.Notify(renewEv); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 5*time.Second, "both events on the all-types receiver", func() bool {
		return len(allRcv.events()) == 2
	})
	waitFor(t, 5*time.Second, "only the renewal on the filtered receiver", func() bool {
		return len(renewRcv.events()) == 1
	})

	if got := renewRcv.events()[0].id; got != renewEv.Payload.EventID {
		t.Errorf("expected only the renewal event on the filtered receiver, got %q", got)
	}
}

func TestDispatcher_SchedulerRecoversStoredEvents(t *testing.T) {
	rcv := &receiver{}
	srv := httptest.NewServer(rcv.handler())
	defer srv.Close()

	store := NewMemoryStore()
	d := NewDispatcher(testOptions(srv.URL, store))
	defer d.Stop()

	rec := &db.EventRecord{
		ID:        "stored-only",
		Type:      TypeX509Signed,
		Status:    db.EventStatusPending,
		Payload:   []byte(`{"eventId":"stored-only","eventType":"x509.signed"}`),
		CreatedAt: time.Now().UTC().Add(-time.Minute),
		UpdatedAt: time.Now().UTC().Add(-time.Minute),
	}
	if err := store.PutEvent(rec); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 5*time.Second, "stored event to be delivered by the scheduler", func() bool {
		return len(rcv.events()) == 1
	})
	if got := rcv.events()[0].id; got != "stored-only" {
		t.Errorf("expected stored event to be delivered, got %q", got)
	}
}

func TestDispatcher_UnreachableWebhook(t *testing.T) {
	store := NewMemoryStore()
	d := NewDispatcher(testOptions("http://127.0.0.1:1", store))
	defer d.Stop()

	ev := testEvent(t, TypeX509Signed)
	if err := d.Notify(ev); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 5*time.Second, "event to be marked failed", func() bool {
		rec, err := store.GetEvent(ev.Payload.EventID)
		return err == nil && rec.Status == db.EventStatusFailed
	})
}

func TestRetryOptions_Backoff(t *testing.T) {
	r := RetryOptions{
		InitialBackoff: time.Second,
		MaxBackoff:     5 * time.Second,
		Multiplier:     2,
	}
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 1 * time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 5 * time.Second},
		{10, 5 * time.Second},
	}
	for _, tc := range tests {
		if got := r.backoff(tc.attempt); got != tc.want {
			t.Errorf("backoff(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}

	empty := RetryOptions{}
	empty.withDefaults()
	if empty.MaxAttempts != DefaultMaxAttempts || empty.InitialBackoff != DefaultInitialBackoff ||
		empty.MaxBackoff != DefaultMaxBackoff || empty.Multiplier != DefaultMultiplier {
		t.Errorf("defaults not applied: %+v", empty)
	}
}
