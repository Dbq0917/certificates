package db

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/nosql"
	"github.com/smallstep/nosql/database"
)

var eventsTable = []byte("events")

// Statuses of an event delivery record.
const (
	EventStatusPending   = "pending"
	EventStatusDelivered = "delivered"
	EventStatusFailed    = "failed"
)

// EventRecord is the durable record of a certificate lifecycle event that is
// pending delivery, delivered, or terminally failed to be delivered to the
// configured event webhooks. It provides the traceability required to
// reconcile the CA event stream with downstream audit systems.
type EventRecord struct {
	// ID uniquely identifies the event. It is stable across retries so
	// that receivers can deduplicate repeated deliveries.
	ID      string `json:"id"`
	Type    string `json:"type"`
	Status  string `json:"status"`
	Payload []byte `json:"payload"`

	// Fingerprint is the SHA-256 fingerprint of the certificate the event
	// is about. PreviousFingerprint links a renewal to the certificate it
	// replaces.
	Fingerprint         string `json:"fingerprint,omitempty"`
	PreviousFingerprint string `json:"previousFingerprint,omitempty"`
	SerialNumber        string `json:"serialNumber,omitempty"`

	Attempts      int        `json:"attempts"`
	LastError     string     `json:"lastError,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
	NextAttemptAt time.Time  `json:"nextAttemptAt,omitempty"`
	DeliveredAt   *time.Time `json:"deliveredAt,omitempty"`
}

// EventStore is the interface used by the event dispatcher to persist and
// query event delivery records.
type EventStore interface {
	PutEvent(rec *EventRecord) error
	GetEvent(id string) (*EventRecord, error)
	ListEvents() ([]*EventRecord, error)
}

// PutEvent creates or updates the given event record.
func (db *DB) PutEvent(rec *EventRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return errors.Wrap(err, "error marshaling event record")
	}
	if err := db.Set(eventsTable, []byte(rec.ID), b); err != nil {
		return errors.Wrap(err, "error storing event record")
	}
	return nil
}

// GetEvent returns the event record with the given id.
func (db *DB) GetEvent(id string) (*EventRecord, error) {
	b, err := db.Get(eventsTable, []byte(id))
	if err != nil {
		if nosql.IsErrNotFound(err) {
			return nil, errors.Wrapf(database.ErrNotFound, "event %s not found", id)
		}
		return nil, errors.Wrap(err, "error getting event record")
	}
	var rec EventRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling event record")
	}
	return &rec, nil
}

// ListEvents returns all stored event records.
func (db *DB) ListEvents() ([]*EventRecord, error) {
	entries, err := db.List(eventsTable)
	if err != nil {
		return nil, errors.Wrap(err, "error listing event records")
	}
	records := make([]*EventRecord, 0, len(entries))
	for _, e := range entries {
		var rec EventRecord
		if err := json.Unmarshal(e.Value, &rec); err != nil {
			return nil, errors.Wrap(err, "error unmarshaling event record")
		}
		records = append(records, &rec)
	}
	return records, nil
}
