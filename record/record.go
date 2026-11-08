// Package record creates, signs, parses and verifies Commonwealth signed
// records, as defined in specs/record-format.md.
//
// A typical issuer creates a record with New, signs it with Sign and sends
// the JSON from Marshal. A receiver calls Parse and then Verify (or
// VerifyWith, to look the issuer's key up in a registry).
package record

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/polycentric-commonwealth/foundation/canonical"
)

// Spec is the envelope format version this package implements.
const Spec = "pc-record/0.1"

// Layer is the layer of government an issuing instance belongs to.
type Layer string

// The four layers.
const (
	Commonwealth Layer = "commonwealth"
	Region       Layer = "region"
	State        Layer = "state"
	Locality     Layer = "locality"
)

// Valid reports whether l is one of the four layers.
func (l Layer) Valid() bool {
	switch l {
	case Commonwealth, Region, State, Locality:
		return true
	}
	return false
}

var (
	// ErrInvalid reports an envelope that does not follow the record format.
	ErrInvalid = errors.New("record: invalid envelope")

	// ErrSignature reports a missing, malformed or incorrect signature.
	ErrSignature = errors.New("record: signature verification failed")
)

// Envelope is a signed record. Payload holds the JSON of the payload object
// exactly as received; it is canonicalized only when signing or verifying.
type Envelope struct {
	Spec       string          `json:"spec"`
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Issuer     string          `json:"issuer"`
	Key        string          `json:"key"`
	Layer      Layer           `json:"layer"`
	IssuedAt   string          `json:"issued_at"`
	Supersedes string          `json:"supersedes,omitempty"`
	Payload    json.RawMessage `json:"payload"`
	Signature  string          `json:"signature,omitempty"`
}

// KeyResolver looks up an issuer's public key, normally from the instance
// registry. It must return an error unless the key is trusted and was valid
// at the given time.
type KeyResolver interface {
	PublicKey(issuer, key string, at time.Time) (ed25519.PublicKey, error)
}

// ValidInstanceID reports whether s is a valid instance identifier: a
// lowercase domain name with at least two labels (specs/instance-registry.md).
func ValidInstanceID(s string) bool {
	return len(s) <= 253 && instanceIDPattern.MatchString(s)
}

// IssuedAtTime returns the envelope's issued_at as a time.
func (e *Envelope) IssuedAtTime() (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, e.IssuedAt)
	if err != nil || !strings.HasSuffix(e.IssuedAt, "Z") {
		return time.Time{}, fmt.Errorf("%w: issued_at must be an RFC 3339 UTC timestamp", ErrInvalid)
	}
	return t, nil
}

// New returns an unsigned envelope with a fresh identifier and the current
// time. The payload may be any value that encodes to a JSON object.
func New(issuer, key string, layer Layer, typ string, payload any) (*Envelope, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrInvalid, err)
	}
	now := time.Now()
	id, err := newUUIDv7(now)
	if err != nil {
		return nil, err
	}
	e := &Envelope{
		Spec:     Spec,
		ID:       id,
		Type:     typ,
		Issuer:   issuer,
		Key:      key,
		Layer:    layer,
		IssuedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339),
		Payload:  data,
	}
	if err := e.validateFields(); err != nil {
		return nil, err
	}
	return e, nil
}

// Parse decodes a JSON envelope and checks that it follows the record
// format. It does not verify the signature; call Verify or VerifyWith.
func Parse(data []byte) (*Envelope, error) {
	// Canonicalizing first rejects duplicate keys, invalid UTF-8 and
	// disallowed numbers anywhere in the envelope.
	if _, err := canonical.Transform(data); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var e Envelope
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := e.validateFields(); err != nil {
		return nil, err
	}
	return &e, nil
}

// Marshal returns the envelope as JSON.
func (e *Envelope) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(e); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SigningBytes returns the bytes that are signed: the canonical form of the
// envelope without its signature.
func (e *Envelope) SigningBytes() ([]byte, error) {
	if err := e.validateFields(); err != nil {
		return nil, err
	}
	unsigned := *e
	unsigned.Signature = ""
	data, err := json.Marshal(&unsigned)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	out, err := canonical.Transform(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return out, nil
}

// Sign signs the envelope with the issuer's private key and sets Signature.
func (e *Envelope) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("record: private key must be %d bytes", ed25519.PrivateKeySize)
	}
	msg, err := e.SigningBytes()
	if err != nil {
		return err
	}
	e.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, msg))
	return nil
}

// Verify checks the envelope's fields and its signature against pub.
func (e *Envelope) Verify(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: public key must be %d bytes", ErrSignature, ed25519.PublicKeySize)
	}
	if e.Signature == "" {
		return fmt.Errorf("%w: envelope is not signed", ErrSignature)
	}
	sig, err := base64.RawURLEncoding.DecodeString(e.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature", ErrSignature)
	}
	msg, err := e.SigningBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return ErrSignature
	}
	return nil
}

// VerifyWith looks up the issuer's key with r and verifies the envelope.
func (e *Envelope) VerifyWith(r KeyResolver) error {
	at, err := e.IssuedAtTime()
	if err != nil {
		return err
	}
	pub, err := r.PublicKey(e.Issuer, e.Key, at)
	if err != nil {
		return fmt.Errorf("%w: key lookup for %q/%q: %w", ErrSignature, e.Issuer, e.Key, err)
	}
	return e.Verify(pub)
}

var (
	uuidV7Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	typePattern   = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*/[1-9][0-9]*$`)

	instanceIDPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

func (e *Envelope) validateFields() error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
	}
	if e.Spec != Spec {
		return invalid("spec must be %q, got %q", Spec, e.Spec)
	}
	if !uuidV7Pattern.MatchString(e.ID) {
		return invalid("id must be a lowercase UUID version 7, got %q", e.ID)
	}
	if !typePattern.MatchString(e.Type) {
		return invalid("type must look like name/1, got %q", e.Type)
	}
	if !ValidInstanceID(e.Issuer) {
		return invalid("issuer must be an instance identifier (a lowercase domain name), got %q", e.Issuer)
	}
	if !validName(e.Key, 64) {
		return invalid("key must be 1 to 64 characters without spaces or control characters")
	}
	if !e.Layer.Valid() {
		return invalid("layer must be commonwealth, region, state or locality, got %q", e.Layer)
	}
	if _, err := e.IssuedAtTime(); err != nil {
		return err
	}
	if e.Supersedes != "" && !uuidV7Pattern.MatchString(e.Supersedes) {
		return invalid("supersedes must be a lowercase UUID version 7")
	}
	if p := bytes.TrimSpace(e.Payload); len(p) == 0 || p[0] != '{' {
		return invalid("payload must be a JSON object")
	}
	if _, err := canonical.Transform(e.Payload); err != nil {
		return invalid("payload: %v", err)
	}
	return nil
}

func validName(s string, max int) bool {
	if s == "" || len([]rune(s)) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// newUUIDv7 returns a UUID version 7 (RFC 9562): a 48-bit Unix millisecond
// timestamp followed by random bits.
func newUUIDv7(t time.Time) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[6:]); err != nil {
		return "", fmt.Errorf("record: generating id: %w", err)
	}
	var ms [8]byte
	binary.BigEndian.PutUint64(ms[:], uint64(t.UnixMilli()))
	copy(b[0:6], ms[2:8])
	b[6] = 0x70 | (b[6] & 0x0f) // version 7
	b[8] = 0x80 | (b[8] & 0x3f) // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
