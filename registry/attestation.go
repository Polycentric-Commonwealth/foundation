package registry

import (
	"crypto/ed25519"

	"github.com/polycentric-commonwealth/foundation/record"
)

// AttestedKey is a key a parent vouches for.
type AttestedKey struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
}

// Attestation is the payload of an instance-attestation/1 record, issued by
// a parent instance about one of its children.
type Attestation struct {
	Subject      string        `json:"subject"`
	SubjectLayer record.Layer  `json:"subject_layer"`
	Keys         []AttestedKey `json:"keys"`
}

// Validate checks the attestation against the specification.
func (a *Attestation) Validate() error {
	if !record.ValidInstanceID(a.Subject) {
		return invalid("subject must be an instance identifier, got %q", a.Subject)
	}
	if !a.SubjectLayer.Valid() || a.SubjectLayer == record.Commonwealth {
		return invalid("subject_layer must be region, state or locality, got %q", a.SubjectLayer)
	}
	if len(a.Keys) == 0 {
		return invalid("keys must list at least one key")
	}
	seen := map[string]bool{}
	for _, k := range a.Keys {
		if !validKeyID(k.ID) {
			return invalid("key id must be 1 to 64 characters without spaces or control characters")
		}
		if _, err := DecodePublicKey(k.PublicKey); err != nil {
			return err
		}
		if seen[k.ID] {
			return invalid("key id %q is listed twice", k.ID)
		}
		seen[k.ID] = true
	}
	return nil
}

// NewAttestation returns an attestation record issued by the parent
// instance issuer, signed with its key keyID.
func NewAttestation(issuer string, issuerLayer record.Layer, keyID string, priv ed25519.PrivateKey, a *Attestation) (*record.Envelope, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if a.Subject == issuer {
		return nil, invalid("an instance cannot attest itself")
	}
	if !AllowedParent(a.SubjectLayer, issuerLayer) {
		return nil, invalid("a %s instance cannot attest a %s instance", issuerLayer, a.SubjectLayer)
	}
	env, err := record.New(issuer, keyID, issuerLayer, AttestationType, a)
	if err != nil {
		return nil, err
	}
	if err := env.Sign(priv); err != nil {
		return nil, err
	}
	return env, nil
}

// ParseAttestation checks that env is a well-formed attestation record. It
// does not verify the signature; Registry.AddAttestation does, using the
// issuer's trusted key.
func ParseAttestation(env *record.Envelope) (*Attestation, error) {
	if env.Type != AttestationType {
		return nil, invalid("record type is %q, not %q", env.Type, AttestationType)
	}
	var a Attestation
	if err := decodeStrict(env.Payload, &a); err != nil {
		return nil, err
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	if a.Subject == env.Issuer {
		return nil, invalid("an instance cannot attest itself")
	}
	return &a, nil
}
