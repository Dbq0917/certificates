package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/smallstep/certificates/db"
)

// Default delivery options.
const (
	DefaultQueueSize      = 1024
	DefaultRateLimit      = 10.0 // deliveries per second
	DefaultMaxAttempts    = 8
	DefaultInitialBackoff = 5 * time.Second
	DefaultMaxBackoff     = 30 * time.Minute
	DefaultMultiplier     = 2.0
	DefaultPollInterval   = 10 * time.Second
)

// HTTPClient is the interface used to deliver events.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Store is the persistence interface used by the dispatcher. *db.DB
// implements it using the existing authority database, so no additional
// storage dependency is required.
type Store interface {
	PutEvent(rec *db.EventRecord) error
	GetEvent(id string) (*db.EventRecord, error)
	ListEvents() ([]*db.EventRecord, error)
}

// Webhook configures a single event receiver.
type Webhook struct {
	// URL is the endpoint events are POSTed to.
	URL string
	// Events lists the event types this receiver subscribes to. An empty
	// list subscribes to all event types.
	Events []string
	// Token, if set, is sent as a bearer token in the Authorization
	// header.
	Token string
}

// subscribes reports whether the webhook subscribes to the given event type.
func (w *Webhook) subscribes(eventType string) bool {
	if len(w.Events) == 0 {
		return true
	}
	for _, t := range w.Events {
		if t == eventType {
			return true
		}
	}
	return false
}

// RetryOptions configures the retry behavior of failed deliveries.
type RetryOptions struct {
	// MaxAttempts is the maximum number of delivery attempts, including
	// the first one. After MaxAttempts the event is marked as failed and
	// remains queryable for reconciliation.
	MaxAttempts int
	// InitialBackoff is the delay before the first retry.
	InitialBackoff time.Duration
	// MaxBackoff caps the exponential backoff.
	MaxBackoff time.Duration
	// Multiplier is the exponential backoff multiplier.
	Multiplier float64
}

func (r *RetryOptions) withDefaults() {
	if r.MaxAttempts <= 0 {
		r.MaxAttempts = DefaultMaxAttempts
	}
	if r.InitialBackoff <= 0 {
		r.InitialBackoff = DefaultInitialBackoff
	}
	if r.MaxBackoff <= 0 {
		r.MaxBackoff = DefaultMaxBackoff
	}
	if r.Multiplier <= 0 {
		r.Multiplier = DefaultMultiplier
	}
}

// backoff returns the delay before the given attempt (1-based).
func (r *RetryOptions) backoff(attempt int) time.Duration {
	d := float64(r.InitialBackoff)
	for i := 1; i < attempt; i++ {
		d *= r.Multiplier
	}
	if d > float64(r.MaxBackoff) {
		return r.MaxBackoff
	}
	return time.Duration(d)
}

// Options configures a Dispatcher.
type Options struct {
	Webhooks []Webhook
	Store    Store
	Client   HTTPClient
	Retry    RetryOptions
	// RateLimit is the maximum number of delivery attempts per second. It
	// throttles delivery when events pile up instead of dropping them.
	RateLimit float64
	// QueueSize is the size of the in-memory delivery queue. Events that
	// do not fit remain persisted and are picked up by the scheduler, so
	// they are delayed, never dropped.
	QueueSize int
	// PollInterval is how often the scheduler reloads due events from the
	// store.
	PollInterval time.Duration
	// Logger, if nil, logs to the standard logger.
	Logger *log.Logger
}

// Stats summarizes the delivery state of all recorded events. After an
// outage, Pending and Failed show exactly how many events have not (yet)
// been delivered, which is the input for reconciliation with the audit
// system.
type Stats struct {
	Pending   int `json:"pending"`
	Delivered int `json:"delivered"`
	Failed    int `json:"failed"`
	Total     int `json:"total"`
}

// Dispatcher delivers certificate lifecycle events to webhook receivers
// with durable retry.
type Dispatcher struct {
	webhooks []Webhook
	store    Store
	client   HTTPClient
	retry    RetryOptions
	limiter  *rate.Limiter
	logger   *log.Logger

	queue        chan *db.EventRecord
	pollInterval time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewDispatcher creates and starts a Dispatcher.
func NewDispatcher(opts Options) *Dispatcher {
	if opts.Store == nil {
		opts.Store = NewMemoryStore()
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = DefaultQueueSize
	}
	if opts.RateLimit <= 0 {
		opts.RateLimit = DefaultRateLimit
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = DefaultPollInterval
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	opts.Retry.withDefaults()

	ctx, cancel := context.WithCancel(context.Background())
	d := &Dispatcher{
		webhooks:     opts.Webhooks,
		store:        opts.Store,
		client:       opts.Client,
		retry:        opts.Retry,
		limiter:      rate.NewLimiter(rate.Limit(opts.RateLimit), 1),
		logger:       opts.Logger,
		queue:        make(chan *db.EventRecord, opts.QueueSize),
		pollInterval: opts.PollInterval,
		ctx:          ctx,
		cancel:       cancel,
	}

	d.wg.Add(2)
	go d.worker()
	go d.scheduler()

	return d
}

// Notify records the given event and schedules its delivery. The event is
// persisted before it is enqueued, so it survives restarts and queue
// overflow. Notify never blocks the caller on delivery.
func (d *Dispatcher) Notify(ev *Event) error {
	now := time.Now().UTC()
	payload, err := json.Marshal(ev.Payload)
	if err != nil {
		return fmt.Errorf("events: error marshaling event payload: %w", err)
	}

	rec := &db.EventRecord{
		ID:      ev.Payload.EventID,
		Type:    ev.Payload.EventType,
		Status:  db.EventStatusPending,
		Payload: payload,
		// Fingerprint and PreviousFingerprint are denormalized onto the
		// record so that reconciliation queries do not need to decode the
		// payload.
		Fingerprint:  ev.Payload.Fingerprint,
		SerialNumber: ev.SerialNumber,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if prev := ev.Payload.PreviousCertificate; prev != nil {
		rec.PreviousFingerprint = prev.Fingerprint
	}

	if err := d.store.PutEvent(rec); err != nil {
		// Continue with in-memory delivery; the event may still reach
		// the receiver even if its record could not be persisted.
		d.logger.Printf("events: error persisting event %s: %v", rec.ID, err)
	}

	d.enqueue(rec)
	return nil
}

// enqueue adds the record to the in-memory queue. If the queue is full the
// record is left in the store and the scheduler will pick it up.
func (d *Dispatcher) enqueue(rec *db.EventRecord) {
	select {
	case d.queue <- rec:
	default:
		d.logger.Printf("events: delivery queue full, event %s remains stored for later delivery", rec.ID)
	}
}

// Stop stops the dispatcher. Events already persisted remain stored and
// will be delivered after a restart.
func (d *Dispatcher) Stop() {
	d.cancel()
	d.wg.Wait()
}

// Stats returns the delivery statistics of all recorded events.
func (d *Dispatcher) Stats() (*Stats, error) {
	records, err := d.store.ListEvents()
	if err != nil {
		return nil, err
	}
	stats := &Stats{Total: len(records)}
	for _, rec := range records {
		switch rec.Status {
		case db.EventStatusDelivered:
			stats.Delivered++
		case db.EventStatusFailed:
			stats.Failed++
		default:
			stats.Pending++
		}
	}
	return stats, nil
}

// List returns the event records matching the given filters. An empty
// status matches all statuses. The zero time disables the from/to filters.
// This is the query interface used for reconciliation with downstream
// audit systems.
func (d *Dispatcher) List(status string, from, to time.Time) ([]*db.EventRecord, error) {
	records, err := d.store.ListEvents()
	if err != nil {
		return nil, err
	}
	out := make([]*db.EventRecord, 0, len(records))
	for _, rec := range records {
		if status != "" && rec.Status != status {
			continue
		}
		if !from.IsZero() && rec.CreatedAt.Before(from) {
			continue
		}
		if !to.IsZero() && rec.CreatedAt.After(to) {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// worker delivers queued events, throttled by the rate limiter.
func (d *Dispatcher) worker() {
	defer d.wg.Done()
	for {
		select {
		case <-d.ctx.Done():
			return
		case rec := <-d.queue:
			if err := d.limiter.Wait(d.ctx); err != nil {
				return
			}
			d.deliver(rec)
		}
	}
}

// scheduler reloads due events from the store. It covers events that could
// not be enqueued in memory (queue full, crash between persist and
// delivery) and retries whose backoff has elapsed.
func (d *Dispatcher) scheduler() {
	defer d.wg.Done()
	ticker := time.NewTicker(d.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.scheduleDue()
		}
	}
}

func (d *Dispatcher) scheduleDue() {
	records, err := d.store.ListEvents()
	if err != nil {
		d.logger.Printf("events: error listing events for scheduling: %v", err)
		return
	}
	now := time.Now().UTC()
	for _, rec := range records {
		if rec.Status != db.EventStatusPending {
			continue
		}
		switch {
		case !rec.NextAttemptAt.IsZero() && !rec.NextAttemptAt.After(now):
			// Retry whose backoff has elapsed.
			d.enqueue(rec)
		case rec.NextAttemptAt.IsZero() && now.Sub(rec.CreatedAt) >= d.pollInterval:
			// Never delivered and not freshly enqueued; the in-memory
			// enqueue was lost (queue full or restart).
			d.enqueue(rec)
		}
	}
}

// deliver attempts to deliver the event to all subscribed webhooks and
// updates the record accordingly.
func (d *Dispatcher) deliver(rec *db.EventRecord) {
	rec.Attempts++
	rec.UpdatedAt = time.Now().UTC()

	if err := d.post(rec); err != nil {
		rec.LastError = err.Error()
		if rec.Attempts >= d.retry.MaxAttempts {
			rec.Status = db.EventStatusFailed
			d.logger.Printf("events: event %s (%s) terminally failed after %d attempts: %v",
				rec.ID, rec.Type, rec.Attempts, err)
		} else {
			rec.NextAttemptAt = rec.UpdatedAt.Add(d.retry.backoff(rec.Attempts))
			d.logger.Printf("events: event %s (%s) delivery attempt %d failed, retrying at %s: %v",
				rec.ID, rec.Type, rec.Attempts, rec.NextAttemptAt.Format(time.RFC3339), err)
		}
	} else {
		now := time.Now().UTC()
		rec.Status = db.EventStatusDelivered
		rec.DeliveredAt = &now
		rec.LastError = ""
		rec.NextAttemptAt = time.Time{}
	}

	if err := d.store.PutEvent(rec); err != nil {
		d.logger.Printf("events: error updating event %s: %v", rec.ID, err)
	}
}

// post delivers the event payload to every subscribed webhook. The same
// event ID is used for every delivery and retry, so receivers can
// deduplicate.
func (d *Dispatcher) post(rec *db.EventRecord) error {
	var errs []error
	for i := range d.webhooks {
		wh := &d.webhooks[i]
		if !wh.subscribes(rec.Type) {
			continue
		}
		if err := d.postOne(wh, rec); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (d *Dispatcher) postOne(wh *Webhook, rec *db.EventRecord) error {
	req, err := http.NewRequestWithContext(d.ctx, http.MethodPost, wh.URL, bytes.NewReader(rec.Payload))
	if err != nil {
		return fmt.Errorf("events: error creating request for %s: %w", wh.URL, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Step-Event-Id", rec.ID)
	req.Header.Set("X-Step-Event-Type", rec.Type)
	if wh.Token != "" {
		req.Header.Set("Authorization", "Bearer "+wh.Token)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("events: error delivering event %s to %s: %w", rec.ID, wh.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("events: error delivering event %s to %s: unexpected status %s", rec.ID, wh.URL, resp.Status)
	}
	return nil
}
