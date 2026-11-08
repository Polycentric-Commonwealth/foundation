package protocol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"
)

// MaxClockSkew is how far in the future a record's issued_at may be.
const MaxClockSkew = 5 * time.Minute

// Handler processes an accepted message. Returning an error refuses the
// message: it is not stored, and the sender gets a receipt with reason
// "refused" and the error text as detail.
type Handler func(ctx context.Context, env *record.Envelope) error

// Store remembers accepted records so duplicates are not processed twice.
type Store interface {
	Seen(id string) (bool, error)
	Accept(env *record.Envelope) error
}

// MemoryStore is a Store kept in memory, for tests and demonstrations.
type MemoryStore struct {
	mu      sync.Mutex
	records map[string]*record.Envelope
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: map[string]*record.Envelope{}}
}

// Seen reports whether a record with this id was accepted.
func (s *MemoryStore) Seen(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.records[id]
	return ok, nil
}

// Accept stores an accepted record.
func (s *MemoryStore) Accept(env *record.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[env.ID] = env
	return nil
}

// Get returns an accepted record by id.
func (s *MemoryStore) Get(id string) (*record.Envelope, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	env, ok := s.records[id]
	return env, ok
}

// Receiver is an http.Handler for an instance's inbox.
type Receiver struct {
	Self     Identity
	Registry *registry.Registry
	Store    Store
	Handlers map[string]Handler

	// Now returns the current time; it defaults to time.Now.
	Now func() time.Time

	// mu serializes the duplicate check, handler and store, so the same
	// record delivered twice at once is processed only once.
	mu sync.Mutex
}

// ServeHTTP accepts a POSTed record and replies with a signed receipt.
func (rv *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	var rc Receipt
	var env *record.Envelope
	switch {
	case err != nil:
		rc = reject("", "", ReasonInvalid, "could not read request body")
	case len(body) > MaxBodyBytes:
		rc = reject("", "", ReasonInvalid, "body larger than 1 MiB")
	default:
		rc, env = rv.Receive(r.Context(), body)
	}

	// Address the receipt to the sender, or to no one if the body could not
	// be parsed or claims to come from this instance itself.
	to := ""
	if env != nil && env.Issuer != rv.Self.Instance {
		to = env.Issuer
	}
	signed, err := rv.Self.Message(to, ReceiptType, rc)
	if err != nil {
		http.Error(w, "could not sign receipt", http.StatusInternalServerError)
		return
	}
	data, err := signed.Marshal()
	if err != nil {
		http.Error(w, "could not encode receipt", http.StatusInternalServerError)
		return
	}

	status := http.StatusOK
	if rc.Status == StatusRejected {
		status = http.StatusUnprocessableEntity
		if env == nil {
			status = http.StatusBadRequest
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}

// Receive runs the delivery checks on a raw record and returns the receipt
// payload and, if the body parsed, the record.
func (rv *Receiver) Receive(ctx context.Context, body []byte) (Receipt, *record.Envelope) {
	env, err := record.Parse(body)
	if err != nil {
		return reject("", "", ReasonInvalid, err.Error()), nil
	}
	id, typ := env.ID, env.Type
	if env.To != rv.Self.Instance {
		return reject(id, typ, ReasonNotAddressed, fmt.Sprintf("record is addressed to %q", env.To)), env
	}
	if !Allowed(typ, env.Layer, rv.Self.Layer) {
		return reject(id, typ, ReasonTypeNotAllowed, fmt.Sprintf("%s may not be sent from %s to %s", typ, env.Layer, rv.Self.Layer)), env
	}
	if desc, ok := rv.Registry.Description(env.Issuer); !ok || desc.Layer != env.Layer {
		return reject(id, typ, ReasonUntrusted, "issuer is unknown or its layer does not match its description"), env
	}
	if err := rv.Registry.Verify(env); err != nil {
		return reject(id, typ, ReasonUntrusted, err.Error()), env
	}
	now := time.Now
	if rv.Now != nil {
		now = rv.Now
	}
	if at, _ := env.IssuedAtTime(); at.After(now().Add(MaxClockSkew)) {
		return reject(id, typ, ReasonFutureDated, "issued_at is in the future"), env
	}

	handle, ok := rv.Handlers[typ]
	if !ok {
		return reject(id, typ, ReasonTypeNotAllowed, "this instance does not process "+typ), env
	}

	rv.mu.Lock()
	defer rv.mu.Unlock()
	seen, err := rv.Store.Seen(id)
	if err != nil {
		return reject(id, typ, ReasonRefused, "storage unavailable; retry later"), env
	}
	if seen {
		return Receipt{Record: id, RecordType: typ, Status: StatusDuplicate}, env
	}
	if err := handle(ctx, env); err != nil {
		return reject(id, typ, ReasonRefused, err.Error()), env
	}
	if err := rv.Store.Accept(env); err != nil {
		return reject(id, typ, ReasonRefused, "storage unavailable; retry later"), env
	}
	return Receipt{Record: id, RecordType: typ, Status: StatusAccepted}, env
}

func reject(id, typ, reason, detail string) Receipt {
	if len(detail) > 1000 {
		detail = detail[:1000]
	}
	return Receipt{Record: id, RecordType: typ, Status: StatusRejected, Reason: reason, Detail: detail}
}

// IsRejected reports whether err is a rejection, and returns its receipt.
func IsRejected(err error) (*Receipt, bool) {
	var re *rejectedError
	if errors.As(err, &re) {
		return re.receipt, true
	}
	return nil, false
}

type rejectedError struct{ receipt *Receipt }

func (e *rejectedError) Error() string {
	return fmt.Sprintf("%v: %s: %s", ErrRejected, e.receipt.Reason, e.receipt.Detail)
}

func (e *rejectedError) Unwrap() error { return ErrRejected }
