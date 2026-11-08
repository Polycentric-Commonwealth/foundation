package registry

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"github.com/polycentric-commonwealth/foundation/record"
)

// Registry holds instance descriptions and attestations a verifier has
// collected, and decides which keys to trust. It is safe for concurrent use.
type Registry struct {
	mu      sync.RWMutex
	anchors map[string]string // instance id -> pinned public key
	entries map[string]*entry
}

// Anchor is a trust anchor: an instance whose identity the verifier pins by
// public key, normally the Commonwealth instance. The anchor's first
// description must be signed by this key; later keys are trusted through
// continuity.
type Anchor struct {
	Instance  string
	PublicKey string // "ed25519:<base64url>"
}

type entry struct {
	desc     *Description
	issuedAt time.Time

	// trusted marks which of desc's keys are trusted.
	trusted map[string]bool

	// attested holds keys vouched for by the parent, by key id, even if no
	// description has arrived yet.
	attested      map[string]string
	attestedBy    string
	attestedLayer record.Layer
}

// New returns an empty registry with the given trust anchors.
func New(anchors ...Anchor) (*Registry, error) {
	r := &Registry{anchors: map[string]string{}, entries: map[string]*entry{}}
	for _, a := range anchors {
		if !record.ValidInstanceID(a.Instance) {
			return nil, invalid("anchor instance %q is not an instance identifier", a.Instance)
		}
		if _, err := DecodePublicKey(a.PublicKey); err != nil {
			return nil, fmt.Errorf("anchor %s: %w", a.Instance, err)
		}
		r.anchors[a.Instance] = a.PublicKey
	}
	return r, nil
}

// pinned reports whether k is the pinned anchor key of instance id.
func (r *Registry) pinned(id string, k Key) bool {
	pub, ok := r.anchors[id]
	return ok && pub == k.PublicKey
}

func (r *Registry) entryFor(id string) *entry {
	e := r.entries[id]
	if e == nil {
		e = &entry{trusted: map[string]bool{}, attested: map[string]string{}}
		r.entries[id] = e
	}
	return e
}

// AddDescription verifies an instance description record and adds it,
// replacing any earlier description of the same instance if the update
// follows the continuity rules.
func (r *Registry) AddDescription(env *record.Envelope) error {
	d, err := ParseDescription(env)
	if err != nil {
		return err
	}
	at, _ := env.IssuedAtTime()

	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.entryFor(d.Instance)

	signer, _ := d.Key(env.Key)
	attestedSigner := e.attested[env.Key] == signer.PublicKey
	var signerTrusted bool

	if e.desc == nil {
		// Later descriptions keep the parent and layer by continuity, so
		// only the first needs checking against any attestation.
		if e.attestedBy != "" && (e.attestedBy != d.Parent || e.attestedLayer != d.Layer) {
			return fmt.Errorf("%w: %s was attested by %s as %s", ErrParent, d.Instance, e.attestedBy, e.attestedLayer)
		}
		signerTrusted = r.pinned(d.Instance, signer) || attestedSigner
	} else {
		if !at.After(e.issuedAt) {
			return ErrStale
		}
		if err := checkContinuity(e.desc, d); err != nil {
			return err
		}
		old, inOld := e.desc.Key(env.Key)
		switch {
		case inOld && old.ValidAt(at):
			signerTrusted = e.trusted[env.Key]
		case attestedSigner:
			// Recovery: the parent has vouched for a replacement key.
			signerTrusted = true
		default:
			return fmt.Errorf("%w: signed by %q, which is neither a valid earlier key nor attested by the parent", ErrContinuity, env.Key)
		}
	}

	trusted := map[string]bool{}
	for _, k := range d.Keys {
		previouslyListed := false
		if e.desc != nil {
			_, previouslyListed = e.desc.Key(k.ID)
		}
		switch {
		case r.pinned(d.Instance, k):
			trusted[k.ID] = true
		case e.attested[k.ID] == k.PublicKey:
			trusted[k.ID] = true
		case previouslyListed:
			trusted[k.ID] = e.trusted[k.ID]
		default:
			// A key first listed in this description inherits the
			// signer's trust.
			trusted[k.ID] = signerTrusted
		}
	}

	e.desc, e.issuedAt, e.trusted = d, at, trusted
	return nil
}

// checkContinuity enforces the update rules in the specification: the same
// layer and parent, and no previously listed key removed, changed or given a
// later end date.
func checkContinuity(old, next *Description) error {
	if old.Layer != next.Layer || old.Parent != next.Parent {
		return fmt.Errorf("%w: layer and parent cannot change", ErrContinuity)
	}
	for _, ok := range old.Keys {
		nk, found := next.Key(ok.ID)
		if !found || nk.PublicKey != ok.PublicKey || nk.ValidFrom != ok.ValidFrom {
			return fmt.Errorf("%w: key %q was removed or changed", ErrContinuity, ok.ID)
		}
		for _, pair := range [][2]string{{ok.ValidUntil, nk.ValidUntil}, {ok.RevokedAt, nk.RevokedAt}} {
			was, now := pair[0], pair[1]
			if was == "" {
				continue
			}
			wt, _ := parseTime(was)
			nt, err := parseTime(now)
			if now == "" || err != nil || nt.After(wt) {
				return fmt.Errorf("%w: key %q end date was removed or moved later", ErrContinuity, ok.ID)
			}
		}
	}
	return nil
}

// AddAttestation verifies an attestation record against its issuer's
// trusted key and records the keys it vouches for.
func (r *Registry) AddAttestation(env *record.Envelope) error {
	a, err := ParseAttestation(env)
	if err != nil {
		return err
	}
	at, _ := env.IssuedAtTime()

	r.mu.Lock()
	defer r.mu.Unlock()

	pub, err := r.publicKey(env.Issuer, env.Key, at)
	if err != nil {
		return fmt.Errorf("attestation issuer: %w", err)
	}
	if err := env.Verify(pub); err != nil {
		return err
	}
	issuer := r.entries[env.Issuer].desc
	if issuer.Layer != env.Layer || !AllowedParent(a.SubjectLayer, issuer.Layer) {
		return fmt.Errorf("%w: a %s instance cannot attest a %s instance", ErrParent, issuer.Layer, a.SubjectLayer)
	}

	e := r.entryFor(a.Subject)
	if e.desc != nil && (e.desc.Parent != env.Issuer || e.desc.Layer != a.SubjectLayer) {
		return fmt.Errorf("%w: %s names %s as its parent", ErrParent, a.Subject, e.desc.Parent)
	}
	if e.attestedBy != "" && e.attestedBy != env.Issuer {
		return fmt.Errorf("%w: %s is already attested by %s", ErrParent, a.Subject, e.attestedBy)
	}

	e.attestedBy, e.attestedLayer = env.Issuer, a.SubjectLayer
	for _, k := range a.Keys {
		e.attested[k.ID] = k.PublicKey
		if e.desc != nil {
			if dk, ok := e.desc.Key(k.ID); ok && dk.PublicKey == k.PublicKey {
				e.trusted[k.ID] = true
			}
		}
	}
	return nil
}

// PublicKey returns the public key issuer used as keyID, if that key is
// trusted and was valid at time at. It implements record.KeyResolver.
func (r *Registry) PublicKey(issuer, keyID string, at time.Time) (ed25519.PublicKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.publicKey(issuer, keyID, at)
}

func (r *Registry) publicKey(issuer, keyID string, at time.Time) (ed25519.PublicKey, error) {
	e := r.entries[issuer]
	if e == nil || e.desc == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownInstance, issuer)
	}
	k, ok := e.desc.Key(keyID)
	if !ok {
		return nil, fmt.Errorf("%w: %s/%s", ErrUnknownKey, issuer, keyID)
	}
	if !k.ValidAt(at) {
		return nil, fmt.Errorf("%w: %s/%s at %s", ErrKeyNotValid, issuer, keyID, at.Format(time.RFC3339))
	}
	if !e.trusted[keyID] {
		return nil, fmt.Errorf("%w: %s/%s", ErrUntrusted, issuer, keyID)
	}
	return DecodePublicKey(k.PublicKey)
}

// Verify checks a record's signature against the registry.
func (r *Registry) Verify(env *record.Envelope) error {
	return env.VerifyWith(r)
}

// Description returns the latest known description of an instance.
func (r *Registry) Description(id string) (*Description, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e := r.entries[id]
	if e == nil || e.desc == nil {
		return nil, false
	}
	return e.desc, true
}
