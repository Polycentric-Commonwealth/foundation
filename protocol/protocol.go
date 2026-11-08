// Package protocol implements the integration protocol: instances send each
// other signed records by POSTing them to an inbox, and the recipient answers
// with a signed receipt (specs/integration-protocol.md).
//
// A Receiver is an http.Handler for an instance's inbox. A Sender delivers
// records to other instances' inboxes and verifies their receipts.
package protocol

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/polycentric-commonwealth/foundation/record"
)

// Protocol constants.
const (
	ReceiptType  = "receipt/1"
	InboxPath    = "inbox"
	MaxBodyBytes = 1 << 20
)

// Route is a permitted direction for a message type, between layers.
type Route struct {
	From, To record.Layer
}

// MessageTypes lists every message type that may be sent to an inbox, and
// between which layers. This table is where the charter's limits on each
// layer's powers are enforced: a type not listed here, or sent along a route
// not listed for it, is refused.
var MessageTypes = map[string][]Route{
	"eligibility-count/1":     {{record.State, record.Commonwealth}},
	"dividend-settlement/1":   {{record.Commonwealth, record.State}},
	"dividend-confirmation/1": {{record.State, record.Commonwealth}},
	"audit-request/1":         {{record.Commonwealth, record.State}},
	"audit-response/1":        {{record.State, record.Commonwealth}},
	"audit-finding/1":         {{record.Commonwealth, record.State}},

	// Uniqueness (specs/federated-identity.md). Evaluation requests go to an
	// operator's evaluation endpoint rather than its inbox.
	"uniqueness-evaluation-request/1": {{record.State, record.Commonwealth}, {record.State, record.Region}},
	"uniqueness-registration/1":       {{record.State, record.Commonwealth}},
	"uniqueness-conflict/1":           {{record.Commonwealth, record.State}},
}

// Allowed reports whether a message of type typ may be sent from layer from
// to layer to.
func Allowed(typ string, from, to record.Layer) bool {
	for _, r := range MessageTypes[typ] {
		if r.From == from && r.To == to {
			return true
		}
	}
	return false
}

// Receipt statuses and rejection reasons.
const (
	StatusAccepted  = "accepted"
	StatusDuplicate = "duplicate"
	StatusRejected  = "rejected"

	ReasonInvalid        = "invalid"
	ReasonNotAddressed   = "not-addressed"
	ReasonTypeNotAllowed = "type-not-allowed"
	ReasonUntrusted      = "untrusted"
	ReasonFutureDated    = "future-dated"
	ReasonRefused        = "refused"
)

// Receipt is the payload of a receipt/1 record.
type Receipt struct {
	Record     string `json:"record"`
	RecordType string `json:"record_type,omitempty"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	Detail     string `json:"detail,omitempty"`

	// Envelope is the signed receipt record itself, kept as proof of
	// delivery. It is not part of the payload.
	Envelope *record.Envelope `json:"-"`
}

// ErrRejected reports a delivery the recipient refused; the Receipt says why.
var ErrRejected = errors.New("protocol: recipient rejected the record")

// Identity is an instance's own identity and signing key.
type Identity struct {
	Instance string
	Layer    record.Layer
	KeyID    string
	Key      ed25519.PrivateKey
}

// Message returns a signed record of type typ addressed to instance to.
func (id Identity) Message(to, typ string, payload any) (*record.Envelope, error) {
	env, err := record.New(id.Instance, id.KeyID, id.Layer, typ, payload)
	if err != nil {
		return nil, err
	}
	env.To = to
	if err := env.Sign(id.Key); err != nil {
		return nil, fmt.Errorf("protocol: signing %s: %w", typ, err)
	}
	return env, nil
}
