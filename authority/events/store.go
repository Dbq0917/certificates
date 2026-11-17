package events

import (
	"sync"

	"github.com/smallstep/nosql/database"

	"github.com/smallstep/certificates/db"
)

// MemoryStore is an in-memory Store. It is used as a fallback when the
// authority database does not support event records, and in tests. Records
// kept here do not survive restarts.
type MemoryStore struct {
	mu      sync.RWMutex
	records map[string]*db.EventRecord
}

// NewMemoryStore returns a new empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]*db.EventRecord)}
}

// PutEvent creates or updates the given event record.
func (s *MemoryStore) PutEvent(rec *db.EventRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cpy := *rec
	s.records[rec.ID] = &cpy
	return nil
}

// GetEvent returns the event record with the given id.
func (s *MemoryStore) GetEvent(id string) (*db.EventRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[id]
	if !ok {
		return nil, database.ErrNotFound
	}
	cpy := *rec
	return &cpy, nil
}

// ListEvents returns all stored event records.
func (s *MemoryStore) ListEvents() ([]*db.EventRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*db.EventRecord, 0, len(s.records))
	for _, rec := range s.records {
		cpy := *rec
		out = append(out, &cpy)
	}
	return out, nil
}
