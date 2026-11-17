package db

import (
	"testing"
	"time"

	"github.com/smallstep/assert"
)

func TestEventStore(t *testing.T) {
	tmpDir := t.TempDir()
	authDB, err := New(&Config{Type: "badger", DataSource: tmpDir})
	assert.FatalError(t, err)
	defer authDB.Shutdown()

	store, ok := authDB.(EventStore)
	assert.Fatal(t, ok, "AuthDB does not implement EventStore")

	now := time.Now().UTC().Truncate(time.Millisecond)
	rec := &EventRecord{
		ID:          "event-1",
		Type:        "x509.signed",
		Status:      EventStatusPending,
		Payload:     []byte(`{"eventId":"event-1"}`),
		Fingerprint: "abc123",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	assert.FatalError(t, store.PutEvent(rec))

	got, err := store.GetEvent("event-1")
	assert.FatalError(t, err)
	assert.Equals(t, rec.ID, got.ID)
	assert.Equals(t, rec.Type, got.Type)
	assert.Equals(t, rec.Status, got.Status)
	assert.Equals(t, rec.Fingerprint, got.Fingerprint)
	assert.Equals(t, string(rec.Payload), string(got.Payload))

	rec.Attempts = 1
	rec.LastError = "connection refused"
	rec.NextAttemptAt = now.Add(time.Minute)
	assert.FatalError(t, store.PutEvent(rec))

	got, err = store.GetEvent("event-1")
	assert.FatalError(t, err)
	assert.Equals(t, 1, got.Attempts)
	assert.Equals(t, "connection refused", got.LastError)
	assert.Equals(t, rec.NextAttemptAt, got.NextAttemptAt)

	deliveredAt := now.Add(time.Second)
	assert.FatalError(t, store.PutEvent(&EventRecord{
		ID:                  "event-2",
		Type:                "x509.renewed",
		Status:              EventStatusDelivered,
		Fingerprint:         "def456",
		PreviousFingerprint: "abc123",
		CreatedAt:           now,
		UpdatedAt:           now,
		DeliveredAt:         &deliveredAt,
	}))

	records, err := store.ListEvents()
	assert.FatalError(t, err)
	assert.Equals(t, 2, len(records))

	_, err = store.GetEvent("does-not-exist")
	assert.Error(t, err)
}
