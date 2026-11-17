package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/smallstep/assert"

	"github.com/smallstep/certificates/authority/events"
	"github.com/smallstep/certificates/db"
)

func TestHandler_GetEvents(t *testing.T) {
	now := time.Now().UTC()
	records := []*db.EventRecord{
		{ID: "event-1", Type: "x509.signed", Status: db.EventStatusDelivered, CreatedAt: now},
		{ID: "event-2", Type: "x509.renewed", Status: db.EventStatusFailed, CreatedAt: now},
	}

	tests := map[string]struct {
		target     string
		auth       adminAuthority
		statusCode int
		wantEvents int
	}{
		"ok": {
			target: "/events?status=failed&from=2026-01-01T00:00:00Z&to=2026-12-31T00:00:00Z",
			auth: &mockAdminAuthority{
				MockListEventRecords: func(status string, from, to time.Time) ([]*db.EventRecord, error) {
					assert.Equals(t, "failed", status)
					assert.False(t, from.IsZero())
					assert.False(t, to.IsZero())
					return records, nil
				},
			},
			statusCode: http.StatusOK,
			wantEvents: 2,
		},
		"ok/no-filters": {
			target: "/events",
			auth: &mockAdminAuthority{
				MockListEventRecords: func(status string, from, to time.Time) ([]*db.EventRecord, error) {
					assert.Equals(t, "", status)
					assert.True(t, from.IsZero())
					assert.True(t, to.IsZero())
					return records, nil
				},
			},
			statusCode: http.StatusOK,
			wantEvents: 2,
		},
		"fail/bad-from": {
			target:     "/events?from=not-a-time",
			auth:       &mockAdminAuthority{},
			statusCode: http.StatusBadRequest,
		},
		"fail/bad-to": {
			target:     "/events?to=not-a-time",
			auth:       &mockAdminAuthority{},
			statusCode: http.StatusBadRequest,
		},
		"fail/store-error": {
			target: "/events",
			auth: &mockAdminAuthority{
				MockListEventRecords: func(status string, from, to time.Time) ([]*db.EventRecord, error) {
					return nil, errors.New("force")
				},
			},
			statusCode: http.StatusInternalServerError,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mockMustAuthority(t, tc.auth)
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			w := httptest.NewRecorder()

			NewEventsAdminResponder().GetEvents(w, req)
			res := w.Result()
			defer res.Body.Close()
			assert.Equals(t, tc.statusCode, res.StatusCode)

			if tc.statusCode == http.StatusOK {
				var resp GetEventsResponse
				assert.FatalError(t, json.NewDecoder(res.Body).Decode(&resp))
				assert.Equals(t, tc.wantEvents, len(resp.Events))
			}
		})
	}
}

func TestHandler_GetEventsStats(t *testing.T) {
	tests := map[string]struct {
		auth       adminAuthority
		statusCode int
		want       *events.Stats
	}{
		"ok": {
			auth: &mockAdminAuthority{
				MockEventDeliveryStats: func() (*events.Stats, error) {
					return &events.Stats{Pending: 1, Delivered: 2, Failed: 3, Total: 6}, nil
				},
			},
			statusCode: http.StatusOK,
			want:       &events.Stats{Pending: 1, Delivered: 2, Failed: 3, Total: 6},
		},
		"fail/store-error": {
			auth: &mockAdminAuthority{
				MockEventDeliveryStats: func() (*events.Stats, error) {
					return nil, errors.New("force")
				},
			},
			statusCode: http.StatusInternalServerError,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			mockMustAuthority(t, tc.auth)
			req := httptest.NewRequest(http.MethodGet, "/events/stats", nil)
			w := httptest.NewRecorder()

			NewEventsAdminResponder().GetEventsStats(w, req)
			res := w.Result()
			defer res.Body.Close()
			assert.Equals(t, tc.statusCode, res.StatusCode)

			if tc.want != nil {
				var stats events.Stats
				assert.FatalError(t, json.NewDecoder(res.Body).Decode(&stats))
				assert.Equals(t, *tc.want, stats)
			}
		})
	}
}
