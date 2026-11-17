// Package events implements asynchronous, durable delivery of certificate
// lifecycle events (issuance, renewal, rekey) to configured webhook
// receivers. It exists to serve security governance and audit requirements:
// every certificate lifecycle transition is recorded and delivered so that
// downstream audit systems observe the complete lifecycle of every
// certificate.
package events

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"go.step.sm/crypto/x509util"

	"github.com/smallstep/certificates/webhook"
)

// Event types emitted by the authority.
const (
	TypeX509Signed  = "x509.signed"
	TypeX509Renewed = "x509.renewed"
	TypeX509Rekeyed = "x509.rekeyed"
)

var errEmptyChain = errors.New("events: certificate chain is empty")

// PreviousCertificate describes the certificate that a renewal or rekey
// event replaces, linking the new certificate to the previous one.
type PreviousCertificate struct {
	SerialNumber string    `json:"serialNumber"`
	Fingerprint  string    `json:"fingerprint"`
	NotBefore    time.Time `json:"notBefore"`
	NotAfter     time.Time `json:"notAfter"`
}

// Payload is the body delivered to event webhook receivers. Field names
// shared with the existing webhook request body (timestamp,
// provisionerName, x509Certificate) keep their meaning and format so that
// existing receivers remain compatible.
type Payload struct {
	// EventID uniquely identifies the event and is stable across retries.
	// Receivers must deduplicate on this field to make repeated delivery
	// idempotent.
	EventID   string    `json:"eventId"`
	EventType string    `json:"eventType"`
	Timestamp time.Time `json:"timestamp"`

	// Fingerprint is the hex encoded SHA-256 fingerprint of the
	// certificate this event is about. It allows audit systems to
	// correlate events with certificates.
	Fingerprint string `json:"fingerprint"`

	ProvisionerName string                   `json:"provisionerName,omitempty"`
	X509Certificate *webhook.X509Certificate `json:"x509Certificate,omitempty"`

	// PreviousCertificate is set on renewal and rekey events and
	// identifies the certificate being replaced.
	PreviousCertificate *PreviousCertificate `json:"previousCertificate,omitempty"`
}

// Event is a certificate lifecycle event to be delivered.
type Event struct {
	Payload *Payload
	// SerialNumber is the decimal serial number of the certificate,
	// denormalized for indexing on the delivery record.
	SerialNumber string
}

// Fingerprint returns the hex encoded SHA-256 fingerprint of the raw
// certificate.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// NewX509Event creates a new event of the given type for the given
// certificate chain. If previous is not nil, the event is linked to the
// certificate it replaces.
func NewX509Event(eventType string, chain []*x509.Certificate, provisionerName string, previous *x509.Certificate) (*Event, error) {
	if len(chain) == 0 || chain[0] == nil {
		return nil, errEmptyChain
	}
	leaf := chain[0]

	payload := &Payload{
		EventID:         uuid.NewString(),
		EventType:       eventType,
		Timestamp:       time.Now().UTC(),
		Fingerprint:     Fingerprint(leaf),
		ProvisionerName: provisionerName,
	}

	cert, err := x509util.NewCertificateFromX509(leaf)
	if err != nil {
		return nil, err
	}
	rb, err := webhook.NewRequestBody(webhook.WithX509Certificate(cert, leaf))
	if err != nil {
		return nil, err
	}
	payload.X509Certificate = rb.X509Certificate

	if previous != nil {
		payload.PreviousCertificate = &PreviousCertificate{
			SerialNumber: previous.SerialNumber.String(),
			Fingerprint:  Fingerprint(previous),
			NotBefore:    previous.NotBefore,
			NotAfter:     previous.NotAfter,
		}
	}

	return &Event{Payload: payload, SerialNumber: leaf.SerialNumber.String()}, nil
}
