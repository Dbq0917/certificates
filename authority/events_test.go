package authority

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/keyutil"

	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/authority/events"
	"github.com/smallstep/certificates/authority/provisioner"
	"github.com/smallstep/certificates/db"
)

// eventCapture is a test audit-side receiver that records delivered event
// payloads.
type eventCapture struct {
	mu       sync.Mutex
	payloads []events.Payload
}

func (c *eventCapture) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p events.Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.payloads = append(c.payloads, p)
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
}

func (c *eventCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.payloads)
}

func (c *eventCapture) get(i int) events.Payload {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.payloads[i]
}

func waitForEvent(t *testing.T, timeout time.Duration, msg string, cond func() bool) {
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

// TestAuthority_LifecycleEvents_SignAndRenew is the primary acceptance test:
// a sign followed by a renewal must produce exactly two audit events, and
// the renewal event must be linked to the originally issued certificate.
func TestAuthority_LifecycleEvents_SignAndRenew(t *testing.T) {
	_, priv, err := keyutil.GenerateDefaultKeyPair()
	require.NoError(t, err)

	a := testAuthority(t)
	a.config.AuthorityConfig.Template = &ASN1DN{
		Country:      "Tazmania",
		Organization: "Acme Co",
		CommonName:   "test.smallstep.com",
	}

	// Use a real authority database for the event records, proving no
	// additional storage dependency is required.
	authDB, err := db.New(&db.Config{Type: "badger", DataSource: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { authDB.Shutdown() })
	a.db = authDB

	capture := &eventCapture{}
	srv := capture.server()
	t.Cleanup(srv.Close)

	a.config.AuthorityConfig.Events = &config.EventsConfig{
		Webhooks: []config.EventWebhook{
			{URL: srv.URL, Events: []string{events.TypeX509Signed, events.TypeX509Renewed}},
		},
	}
	a.initEvents()
	require.NotNil(t, a.events)
	t.Cleanup(a.events.Stop)

	// Authorize a token to get the sign options, as in the regular sign
	// flow.
	key, err := jose.ReadKey("testdata/secrets/step_cli_key_priv.jwk", jose.WithPassword([]byte("pass")))
	require.NoError(t, err)
	token, err := generateToken("smallstep test", "step-cli", testAudiences.Sign[0], []string{"test.smallstep.com"}, time.Now(), key)
	require.NoError(t, err)
	ctx := provisioner.NewContextWithMethod(context.Background(), provisioner.SignMethod)
	extraOpts, err := a.Authorize(ctx, token)
	require.NoError(t, err)

	nb := time.Now()
	signOpts := provisioner.SignOptions{
		NotBefore: provisioner.NewTimeDuration(nb),
		NotAfter:  provisioner.NewTimeDuration(nb.Add(5 * time.Minute)),
		Backdate:  time.Minute,
	}

	// 1. Issue.
	csr := getCSR(t, priv)
	chain, err := a.SignWithContext(context.Background(), csr, signOpts, extraOpts...)
	require.NoError(t, err)
	require.NotEmpty(t, chain)

	// 2. Renew.
	renewed, err := a.Renew(chain[0])
	require.NoError(t, err)
	require.NotEmpty(t, renewed)

	// The audit side must receive exactly two events.
	waitForEvent(t, 10*time.Second, "two events to be delivered", func() bool {
		return capture.count() == 2
	})

	signedPayload := capture.get(0)
	require.Equal(t, events.TypeX509Signed, signedPayload.EventType)
	require.NotEmpty(t, signedPayload.EventID)
	require.Equal(t, events.Fingerprint(chain[0]), signedPayload.Fingerprint)
	require.Equal(t, "step-cli", signedPayload.ProvisionerName)
	require.NotNil(t, signedPayload.X509Certificate)
	require.Nil(t, signedPayload.PreviousCertificate)

	renewedPayload := capture.get(1)
	require.Equal(t, events.TypeX509Renewed, renewedPayload.EventType)
	require.NotEmpty(t, renewedPayload.EventID)
	require.NotEqual(t, signedPayload.EventID, renewedPayload.EventID)
	require.Equal(t, events.Fingerprint(renewed[0]), renewedPayload.Fingerprint)

	// The renewal must be linked to the certificate it replaces.
	require.NotNil(t, renewedPayload.PreviousCertificate)
	require.Equal(t, signedPayload.Fingerprint, renewedPayload.PreviousCertificate.Fingerprint)
	require.Equal(t, chain[0].SerialNumber.String(), renewedPayload.PreviousCertificate.SerialNumber)

	// The delivery records in the CA database must show the same two
	// linked events, both delivered.
	waitForEvent(t, 10*time.Second, "two delivered records", func() bool {
		records, err := a.ListEventRecords(db.EventStatusDelivered, time.Time{}, time.Time{})
		return err == nil && len(records) == 2
	})
	records, err := a.ListEventRecords("", time.Time{}, time.Time{})
	require.NoError(t, err)
	require.Len(t, records, 2)

	var signedRec, renewedRec *db.EventRecord
	for _, rec := range records {
		switch rec.Type {
		case events.TypeX509Signed:
			signedRec = rec
		case events.TypeX509Renewed:
			renewedRec = rec
		}
	}
	require.NotNil(t, signedRec)
	require.NotNil(t, renewedRec)
	require.Equal(t, db.EventStatusDelivered, signedRec.Status)
	require.Equal(t, db.EventStatusDelivered, renewedRec.Status)
	require.Equal(t, signedRec.Fingerprint, renewedRec.PreviousFingerprint)

	stats, err := a.EventDeliveryStats()
	require.NoError(t, err)
	require.Equal(t, &events.Stats{Delivered: 2, Total: 2}, stats)
}

// TestAuthority_LifecycleEvents_UnreachableWebhook is the second acceptance
// test: when the callback is unreachable, the renewal itself must still
// succeed, and the failed delivery must be retried and remain queryable.
func TestAuthority_LifecycleEvents_UnreachableWebhook(t *testing.T) {
	a := testAuthority(t)
	a.config.AuthorityConfig.Template = &ASN1DN{
		Country:      "Tazmania",
		Organization: "Acme Co",
		CommonName:   "renew",
	}

	a.events = events.NewDispatcher(events.Options{
		Webhooks: []events.Webhook{{URL: "http://127.0.0.1:1"}}, // nothing listens here
		Retry: events.RetryOptions{
			MaxAttempts:    2,
			InitialBackoff: 5 * time.Millisecond,
			MaxBackoff:     10 * time.Millisecond,
			Multiplier:     2,
		},
		RateLimit:    1000,
		PollInterval: 10 * time.Millisecond,
	})
	t.Cleanup(a.events.Stop)

	now := time.Now().UTC()
	issuer := getDefaultIssuer(a)
	signer := getDefaultSigner(a)
	cert := generateCertificate(t, "renew", []string{"test.smallstep.com"},
		withNotBeforeNotAfter(now.Add(-time.Minute), now.Add(time.Hour)),
		withDefaultASN1DN(a.config.AuthorityConfig.Template),
		withProvisionerOID("Max", a.config.AuthorityConfig.Provisioners[0].(*provisioner.JWK).Key.KeyID),
		withSigner(issuer, signer))

	// The renewal itself must succeed even though the callback is
	// unreachable.
	renewed, err := a.Renew(cert)
	require.NoError(t, err)
	require.NotEmpty(t, renewed)

	// The failed delivery must be retried up to the limit and remain
	// queryable.
	waitForEvent(t, 10*time.Second, "renewal event to be marked failed", func() bool {
		records, err := a.ListEventRecords(db.EventStatusFailed, time.Time{}, time.Time{})
		return err == nil && len(records) == 1
	})

	records, err := a.ListEventRecords(db.EventStatusFailed, time.Time{}, time.Time{})
	require.NoError(t, err)
	require.Len(t, records, 1)
	rec := records[0]
	require.Equal(t, events.TypeX509Renewed, rec.Type)
	require.Equal(t, 2, rec.Attempts)
	require.NotEmpty(t, rec.LastError)
	require.Equal(t, events.Fingerprint(renewed[0]), rec.Fingerprint)
	require.Equal(t, events.Fingerprint(cert), rec.PreviousFingerprint)

	// The outage is visible in the delivery stats: one event could not be
	// delivered.
	stats, err := a.EventDeliveryStats()
	require.NoError(t, err)
	require.Equal(t, 1, stats.Failed)
	require.Equal(t, 1, stats.Total)
}

// TestAuthority_LifecycleEvents_NotConfigured verifies that the CA behaves
// exactly as before when no event webhooks are configured.
func TestAuthority_LifecycleEvents_NotConfigured(t *testing.T) {
	a := testAuthority(t)
	a.config.AuthorityConfig.Template = &ASN1DN{
		Country:      "Tazmania",
		Organization: "Acme Co",
		CommonName:   "renew",
	}
	require.Nil(t, a.events)

	now := time.Now().UTC()
	cert := generateCertificate(t, "renew", []string{"test.smallstep.com"},
		withNotBeforeNotAfter(now.Add(-time.Minute), now.Add(time.Hour)),
		withDefaultASN1DN(a.config.AuthorityConfig.Template),
		withProvisionerOID("Max", a.config.AuthorityConfig.Provisioners[0].(*provisioner.JWK).Key.KeyID),
		withSigner(getDefaultIssuer(a), getDefaultSigner(a)))

	renewed, err := a.Renew(cert)
	require.NoError(t, err)
	require.NotEmpty(t, renewed)

	records, err := a.ListEventRecords("", time.Time{}, time.Time{})
	require.NoError(t, err)
	require.Empty(t, records)

	stats, err := a.EventDeliveryStats()
	require.NoError(t, err)
	require.Equal(t, &events.Stats{}, stats)
}
