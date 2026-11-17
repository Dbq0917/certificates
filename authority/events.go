package authority

import (
	"crypto/x509"
	"log"
	"time"

	"github.com/smallstep/certificates/authority/events"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
)

// initEvents initializes the lifecycle event dispatcher from the authority
// configuration. It is a no-op when no event webhooks are configured.
func (a *Authority) initEvents() {
	cfg := a.config.AuthorityConfig.Events
	if cfg == nil || len(cfg.Webhooks) == 0 {
		return
	}

	// Persist event records in the existing authority database when
	// possible; no additional storage dependency is introduced. Fall back
	// to an in-memory store otherwise.
	var store events.Store
	if es, ok := a.db.(db.EventStore); ok {
		store = es
	} else {
		log.Println("authority database does not support event records; using in-memory event store, event delivery records will not survive restarts")
		store = events.NewMemoryStore()
	}

	opts := events.Options{
		Store:     store,
		Client:    a.webhookClient,
		QueueSize: cfg.QueueSize,
		RateLimit: cfg.RateLimit,
	}
	for _, wh := range cfg.Webhooks {
		opts.Webhooks = append(opts.Webhooks, events.Webhook{
			URL:    wh.URL,
			Events: wh.Events,
			Token:  wh.Token,
		})
	}
	if r := cfg.Retry; r != nil {
		opts.Retry.MaxAttempts = r.MaxAttempts
		opts.Retry.Multiplier = r.Multiplier
		if r.InitialBackoff != nil {
			opts.Retry.InitialBackoff = r.InitialBackoff.Duration
		}
		if r.MaxBackoff != nil {
			opts.Retry.MaxBackoff = r.MaxBackoff.Duration
		}
	}

	a.events = events.NewDispatcher(opts)
}

// notifyEvent emits a certificate lifecycle event. Delivery happens
// asynchronously and its failures are retried by the dispatcher; they never
// affect the certificate operation itself.
func (a *Authority) notifyEvent(eventType string, chain []*x509.Certificate, prov provisioner.Interface, previous *x509.Certificate) {
	if a.events == nil || len(chain) == 0 || chain[0] == nil {
		return
	}
	var provisionerName string
	if prov != nil {
		provisionerName = prov.GetName()
	}
	ev, err := events.NewX509Event(eventType, chain, provisionerName, previous)
	if err != nil {
		log.Printf("error creating %s event: %v", eventType, err)
		return
	}
	if err := a.events.Notify(ev); err != nil {
		log.Printf("error notifying %s event: %v", eventType, err)
	}
}

// ListEventRecords returns the event delivery records matching the given
// filters. It is the query interface used to reconcile the CA event stream
// with downstream audit systems. When event delivery is not configured it
// returns an empty list and no error.
func (a *Authority) ListEventRecords(status string, from, to time.Time) ([]*db.EventRecord, error) {
	if a.events == nil {
		return []*db.EventRecord{}, nil
	}
	return a.events.List(status, from, to)
}

// EventDeliveryStats returns the delivery statistics of all recorded
// events. After an outage, the pending and failed counts show exactly how
// many events have not (yet) been delivered. When event delivery is not
// configured it returns zeroed stats and no error.
func (a *Authority) EventDeliveryStats() (*events.Stats, error) {
	if a.events == nil {
		return &events.Stats{}, nil
	}
	return a.events.Stats()
}
