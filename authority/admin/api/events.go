package api

import (
	"net/http"
	"time"

	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/authority/admin"
	"github.com/smallstep/certificates/db"
)

// GetEventsResponse is the response of the GetEvents endpoint.
type GetEventsResponse struct {
	Events []*db.EventRecord `json:"events"`
}

// EventsAdminResponder is the interface responsible for writing certificate
// lifecycle event delivery responses.
type EventsAdminResponder interface {
	GetEvents(w http.ResponseWriter, r *http.Request)
	GetEventsStats(w http.ResponseWriter, r *http.Request)
}

// eventsAdminResponder implements EventsAdminResponder.
type eventsAdminResponder struct{}

// NewEventsAdminResponder returns a new EventsAdminResponder.
func NewEventsAdminResponder() EventsAdminResponder {
	return &eventsAdminResponder{}
}

// GetEvents lists the certificate lifecycle event delivery records, filtered
// by the status, from and to query parameters. Audit systems use this
// endpoint to reconcile their records against the CA event stream: every
// event the CA emitted is listed here with its delivery status, so records
// missing on the audit side can be enumerated automatically.
func (r *eventsAdminResponder) GetEvents(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	status := query.Get("status")

	var from, to time.Time
	var err error
	if v := query.Get("from"); v != "" {
		if from, err = time.Parse(time.RFC3339, v); err != nil {
			render.Error(w, req, admin.WrapError(admin.ErrorBadRequestType, err, "invalid from query parameter, expected RFC3339"))
			return
		}
	}
	if v := query.Get("to"); v != "" {
		if to, err = time.Parse(time.RFC3339, v); err != nil {
			render.Error(w, req, admin.WrapError(admin.ErrorBadRequestType, err, "invalid to query parameter, expected RFC3339"))
			return
		}
	}

	records, err := mustAuthority(req.Context()).ListEventRecords(status, from, to)
	if err != nil {
		render.Error(w, req, admin.WrapErrorISE(err, "error listing event records"))
		return
	}

	render.JSON(w, req, &GetEventsResponse{
		Events: records,
	})
}

// GetEventsStats returns the delivery statistics of all recorded events.
// After an outage, the pending and failed counts show exactly how many
// events have not (yet) been delivered to the audit system.
func (r *eventsAdminResponder) GetEventsStats(w http.ResponseWriter, req *http.Request) {
	stats, err := mustAuthority(req.Context()).EventDeliveryStats()
	if err != nil {
		render.Error(w, req, admin.WrapErrorISE(err, "error getting event delivery stats"))
		return
	}

	render.JSON(w, req, stats)
}
