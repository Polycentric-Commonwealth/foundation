// Package registry implements the instance registry: signed instance
// descriptions, parent attestations, and a Registry that decides which keys
// to trust, as defined in specs/instance-registry.md.
//
// A Registry is a record.KeyResolver, so records can be verified against it
// with envelope.VerifyWith(registry).
package registry

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/polycentric-commonwealth/foundation/record"
)

// Record types and the well-known publication path.
const (
	DescriptionType = "instance-description/1"
	AttestationType = "instance-attestation/1"
	WellKnownPath   = "/.well-known/pc-instance"
)

const publicKeyPrefix = "ed25519:"

var (
	ErrInvalid         = errors.New("registry: invalid")
	ErrUnknownInstance = errors.New("registry: unknown instance")
	ErrUnknownKey      = errors.New("registry: unknown key")
	ErrKeyNotValid     = errors.New("registry: key was not valid at that time")
	ErrUntrusted       = errors.New("registry: key is not trusted")
	ErrContinuity      = errors.New("registry: description breaks continuity with the previous one")
	ErrStale           = errors.New("registry: description is not newer than the one already known")
	ErrParent          = errors.New("registry: attestation does not match the instance's parent")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Key is one signing key in an instance description.
type Key struct {
	ID         string `json:"id"`
	PublicKey  string `json:"public_key"`
	ValidFrom  string `json:"valid_from"`
	ValidUntil string `json:"valid_until,omitempty"`
	RevokedAt  string `json:"revoked_at,omitempty"`
}

// ValidAt reports whether the key could sign at time t. It assumes the key
// has passed Description.Validate.
func (k Key) ValidAt(t time.Time) bool {
	from, err := parseTime(k.ValidFrom)
	if err != nil || t.Before(from) {
		return false
	}
	for _, end := range []string{k.ValidUntil, k.RevokedAt} {
		if end == "" {
			continue
		}
		if until, err := parseTime(end); err != nil || !t.Before(until) {
			return false
		}
	}
	return true
}

// EncodePublicKey returns the "ed25519:<base64url>" form of a public key.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return publicKeyPrefix + base64.RawURLEncoding.EncodeToString(pub)
}

// DecodePublicKey parses the "ed25519:<base64url>" form of a public key.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	raw, ok := strings.CutPrefix(s, publicKeyPrefix)
	if !ok {
		return nil, invalid("public key must start with %q", publicKeyPrefix)
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, invalid("public key must be %d bytes of unpadded base64url", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// Description is the payload of an instance-description/1 record.
type Description struct {
	Instance  string            `json:"instance"`
	Layer     record.Layer      `json:"layer"`
	Name      string            `json:"name"`
	Parent    string            `json:"parent,omitempty"`
	Endpoints map[string]string `json:"endpoints"`
	Keys      []Key             `json:"keys"`
}

// Key returns the key with the given id.
func (d *Description) Key(id string) (Key, bool) {
	for _, k := range d.Keys {
		if k.ID == id {
			return k, true
		}
	}
	return Key{}, false
}

var endpointNamePattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// Validate checks the description against the specification.
func (d *Description) Validate() error {
	if !record.ValidInstanceID(d.Instance) {
		return invalid("instance must be an instance identifier, got %q", d.Instance)
	}
	if !d.Layer.Valid() {
		return invalid("layer %q is not one of the four layers", d.Layer)
	}
	if n := len([]rune(d.Name)); n == 0 || n > 200 || strings.IndexFunc(d.Name, unicode.IsControl) >= 0 {
		return invalid("name must be 1 to 200 characters without control characters")
	}
	if d.Layer == record.Commonwealth {
		if d.Parent != "" {
			return invalid("the commonwealth instance must not have a parent")
		}
	} else if !record.ValidInstanceID(d.Parent) || d.Parent == d.Instance {
		return invalid("parent must be another instance's identifier, got %q", d.Parent)
	}
	if _, ok := d.Endpoints["base"]; !ok {
		return invalid("endpoints must include base")
	}
	for name, raw := range d.Endpoints {
		if len(name) > 64 || !endpointNamePattern.MatchString(name) {
			return invalid("endpoint name %q must be lowercase letters, digits and hyphens", name)
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return invalid("endpoint %s must be an https URL, got %q", name, raw)
		}
	}
	if len(d.Keys) == 0 {
		return invalid("keys must list at least one key")
	}
	seen := map[string]bool{}
	for _, k := range d.Keys {
		if err := validateKey(k); err != nil {
			return err
		}
		if seen[k.ID] {
			return invalid("key id %q is listed twice", k.ID)
		}
		seen[k.ID] = true
	}
	return nil
}

func validateKey(k Key) error {
	if !validKeyID(k.ID) {
		return invalid("key id must be 1 to 64 characters without spaces or control characters")
	}
	if _, err := DecodePublicKey(k.PublicKey); err != nil {
		return fmt.Errorf("key %s: %w", k.ID, err)
	}
	from, err := parseTime(k.ValidFrom)
	if err != nil {
		return invalid("key %s valid_from: %v", k.ID, err)
	}
	if k.ValidUntil != "" {
		until, err := parseTime(k.ValidUntil)
		if err != nil {
			return invalid("key %s valid_until: %v", k.ID, err)
		}
		if !until.After(from) {
			return invalid("key %s valid_until must be after valid_from", k.ID)
		}
	}
	if k.RevokedAt != "" {
		if _, err := parseTime(k.RevokedAt); err != nil {
			return invalid("key %s revoked_at: %v", k.ID, err)
		}
	}
	return nil
}

// AllowedParent reports whether an instance at layer child may have a parent
// at layer parent.
func AllowedParent(child, parent record.Layer) bool {
	switch child {
	case record.Region:
		return parent == record.Commonwealth
	case record.State:
		return parent == record.Region || parent == record.Commonwealth
	case record.Locality:
		return parent == record.State
	}
	return false
}

// NewDescription returns a description record for d, signed with the listed
// key keyID, whose private key is priv.
func NewDescription(d *Description, keyID string, priv ed25519.PrivateKey) (*record.Envelope, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	k, ok := d.Key(keyID)
	if !ok {
		return nil, invalid("signing key %q is not listed in the description", keyID)
	}
	if err := matchesPrivate(k.PublicKey, priv); err != nil {
		return nil, err
	}
	env, err := record.New(d.Instance, keyID, d.Layer, DescriptionType, d)
	if err != nil {
		return nil, err
	}
	if at, _ := env.IssuedAtTime(); !k.ValidAt(at) {
		return nil, fmt.Errorf("%w: signing key %q", ErrKeyNotValid, keyID)
	}
	if err := env.Sign(priv); err != nil {
		return nil, err
	}
	return env, nil
}

// ParseDescription checks that env is a valid description record and that it
// is correctly signed by one of its own keys. It does not decide whether
// those keys are trusted; that is the Registry's job.
func ParseDescription(env *record.Envelope) (*Description, error) {
	if env.Type != DescriptionType {
		return nil, invalid("record type is %q, not %q", env.Type, DescriptionType)
	}
	var d Description
	if err := decodeStrict(env.Payload, &d); err != nil {
		return nil, err
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if env.Issuer != d.Instance || env.Layer != d.Layer {
		return nil, invalid("record issuer and layer must match the description")
	}
	k, ok := d.Key(env.Key)
	if !ok {
		return nil, invalid("signing key %q is not listed in the description", env.Key)
	}
	at, err := env.IssuedAtTime()
	if err != nil {
		return nil, err
	}
	if !k.ValidAt(at) {
		return nil, fmt.Errorf("%w: signing key %q", ErrKeyNotValid, env.Key)
	}
	pub, _ := DecodePublicKey(k.PublicKey)
	if err := env.Verify(pub); err != nil {
		return nil, err
	}
	return &d, nil
}

func matchesPrivate(encodedPub string, priv ed25519.PrivateKey) error {
	pub, err := DecodePublicKey(encodedPub)
	if err != nil {
		return err
	}
	if len(priv) != ed25519.PrivateKeySize || !pub.Equal(priv.Public()) {
		return invalid("private key does not match the listed public key")
	}
	return nil
}

func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("payload: %v", err)
	}
	return nil
}

func parseTime(s string) (time.Time, error) {
	if !strings.HasSuffix(s, "Z") {
		return time.Time{}, errors.New("must be an RFC 3339 UTC time ending in Z")
	}
	return time.Parse(time.RFC3339Nano, s)
}

func validKeyID(s string) bool {
	if s == "" || len([]rune(s)) > 64 {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) < 0
}
