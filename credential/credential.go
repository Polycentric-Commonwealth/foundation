// Package credential implements State-issued credentials and their
// presentation (specs/federated-identity.md#credentials).
//
// A State issues a resident a credential: a signed record saying that the
// holder of a given key is, for example, a resident adult of the State. The
// credential names one audience, the instance that will check it, and the
// resident uses a different key for each audience, so audiences cannot link
// their records of the same person. To present a credential, the holder
// signs the audience's fresh challenge with the credential's key.
//
// Credentials carry no name, number or other identifier of the person, and
// are never logged or sent to an inbox; the holder carries them.
package credential

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"time"

	"github.com/polycentric-commonwealth/foundation/canonical"
	"github.com/polycentric-commonwealth/foundation/protocol"
	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"
)

// Record types, labels and limits.
const (
	Type           = "resident-credential/1"
	StatusListType = "credential-status-list/1"

	// PresentationSpec labels the bytes a holder signs.
	PresentationSpec = "pc-presentation/1"

	// MaxValidity is the longest a credential may be valid.
	MaxValidity = 400 * 24 * time.Hour
	// ChallengeTTL is how long a verifier accepts an answer to its challenge.
	ChallengeTTL = 5 * time.Minute
	// MaxStatusAge is how old a status list may be when a verifier relies on it.
	MaxStatusAge = 24 * time.Hour
	// MaxStatusSize is the most entries in one status list.
	MaxStatusSize = 1 << 20
)

// Claims a credential can make. Each is a statement the issuing State
// vouches for at issue time; a State issues only the claims an audience
// needs.
const (
	ClaimResident         = "resident"
	ClaimAdult            = "adult"
	ClaimDividendEligible = "dividend-eligible"
)

var knownClaims = []string{ClaimAdult, ClaimDividendEligible, ClaimResident}

// Errors returned by verification.
var (
	ErrInvalid = errors.New("credential: invalid")
	ErrRefused = errors.New("credential: not accepted")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func refused(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

var (
	b64         = base64.RawURLEncoding
	listPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

// Status points to a credential's entry in its issuer's status list.
type Status struct {
	List  string `json:"list"`
	Index int64  `json:"index"`
}

// Credential is the payload of resident-credential/1.
type Credential struct {
	Holder     string   `json:"holder"`
	Audience   string   `json:"audience"`
	Claims     []string `json:"claims"`
	ValidFrom  string   `json:"valid_from"`
	ValidUntil string   `json:"valid_until"`
	Status     *Status  `json:"status,omitempty"`
}

// Validate checks the credential's fields.
func (c *Credential) Validate() error {
	if _, err := registry.DecodePublicKey(c.Holder); err != nil {
		return invalid("holder: %v", err)
	}
	if !record.ValidInstanceID(c.Audience) {
		return invalid("audience must be an instance identifier")
	}
	if len(c.Claims) == 0 || !slices.IsSorted(c.Claims) || len(slices.Compact(slices.Clone(c.Claims))) != len(c.Claims) {
		return invalid("claims must be a non-empty sorted list without repeats")
	}
	for _, cl := range c.Claims {
		if !slices.Contains(knownClaims, cl) {
			return invalid("unknown claim %q", cl)
		}
	}
	from, err1 := parseTime(c.ValidFrom)
	until, err2 := parseTime(c.ValidUntil)
	if err1 != nil || err2 != nil {
		return invalid("valid_from and valid_until must be UTC times ending in Z")
	}
	if !until.After(from) || until.Sub(from) > MaxValidity {
		return invalid("validity must be positive and at most %d days", int(MaxValidity.Hours()/24))
	}
	if c.Status != nil {
		if !listPattern.MatchString(c.Status.List) || c.Status.Index < 0 || c.Status.Index >= MaxStatusSize {
			return invalid("status must name a list and an index below %d", MaxStatusSize)
		}
	}
	return nil
}

// Has reports whether the credential makes a claim.
func (c *Credential) Has(claim string) bool { return slices.Contains(c.Claims, claim) }

func parseTime(s string) (time.Time, error) {
	if len(s) == 0 || s[len(s)-1] != 'Z' {
		return time.Time{}, errors.New("not UTC")
	}
	return time.Parse(time.RFC3339, s)
}

// Issue returns a signed credential from a State.
func Issue(state protocol.Identity, c *Credential) (*record.Envelope, error) {
	if state.Layer != record.State {
		return nil, invalid("only States issue credentials")
	}
	c.Claims = slices.Clone(c.Claims)
	slices.Sort(c.Claims)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return state.Message("", Type, c)
}

// Decode returns the validated payload of a credential record.
func Decode(env *record.Envelope) (*Credential, error) {
	var c Credential
	if err := decode(env, Type, &c); err != nil {
		return nil, err
	}
	return &c, c.Validate()
}

// Challenge is a verifier's request for a presentation. The verifier keeps
// it until the answer arrives.
type Challenge struct {
	Audience string `json:"audience"`
	Nonce    string `json:"nonce"`
	IssuedAt string `json:"issued_at"`
}

// NewChallenge returns a fresh challenge from the verifier audience.
func NewChallenge(audience string) (Challenge, error) {
	var n [32]byte
	if _, err := rand.Read(n[:]); err != nil {
		return Challenge{}, err
	}
	return Challenge{
		Audience: audience,
		Nonce:    b64.EncodeToString(n[:]),
		IssuedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
	}, nil
}

// Presentation is a credential with the holder's signature over a challenge.
type Presentation struct {
	Credential *record.Envelope `json:"credential"`
	Nonce      string           `json:"nonce"`
	Signature  string           `json:"signature"`
}

// signingBytes are the canonical JSON the holder signs.
func signingBytes(credentialID string, ch Challenge) ([]byte, error) {
	return canonical.Marshal(map[string]string{
		"spec":       PresentationSpec,
		"credential": credentialID,
		"audience":   ch.Audience,
		"nonce":      ch.Nonce,
	})
}

// Present answers a challenge with a credential and the holder's key.
func Present(cred *record.Envelope, holder ed25519.PrivateKey, ch Challenge) (*Presentation, error) {
	c, err := Decode(cred)
	if err != nil {
		return nil, err
	}
	if c.Holder != registry.EncodePublicKey(holder.Public().(ed25519.PublicKey)) {
		return nil, invalid("key is not the credential's holder key")
	}
	if c.Audience != ch.Audience {
		return nil, invalid("credential is for %s, not %s", c.Audience, ch.Audience)
	}
	msg, err := signingBytes(cred.ID, ch)
	if err != nil {
		return nil, err
	}
	return &Presentation{Credential: cred, Nonce: ch.Nonce, Signature: b64.EncodeToString(ed25519.Sign(holder, msg))}, nil
}

// Verified is what a verifier learns from an accepted presentation.
type Verified struct {
	Issuer     string
	Credential string
	Holder     string
	Claims     []string
	ValidUntil time.Time
}

// Verifier checks presentations made to one audience.
type Verifier struct {
	Audience string
	Registry *registry.Registry

	// StatusList returns the issuer's current status list of the given
	// name, as a signed record. It is needed only for credentials with a
	// status entry.
	StatusList func(issuer, list string) (*record.Envelope, error)

	// Now returns the current time; it defaults to time.Now.
	Now func() time.Time
}

// Verify checks a presentation against the challenge the verifier issued
// and returns what it proves. The error matches ErrInvalid for malformed
// input and ErrRefused for a well-formed presentation that is not accepted.
func (v *Verifier) Verify(p *Presentation, ch Challenge) (*Verified, error) {
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if ch.Audience != v.Audience || p.Nonce != ch.Nonce {
		return nil, refused("presentation does not answer this verifier's challenge")
	}
	if at, err := parseTime(ch.IssuedAt); err != nil || now.Sub(at) > ChallengeTTL || at.After(now.Add(protocol.MaxClockSkew)) {
		return nil, refused("challenge has expired")
	}
	if p.Credential == nil {
		return nil, invalid("no credential")
	}
	env := p.Credential
	c, err := Decode(env)
	if err != nil {
		return nil, err
	}
	if desc, ok := v.Registry.Description(env.Issuer); !ok || desc.Layer != record.State || env.Layer != record.State {
		return nil, refused("issuer %s is not a known State", env.Issuer)
	}
	if err := v.Registry.Verify(env); err != nil {
		return nil, refused("issuer signature: %v", err)
	}
	if revoked, ok := v.Registry.RevokedAt(env.Issuer, env.Key); ok && !now.Before(revoked) {
		return nil, refused("issuer's signing key has been revoked; ask the State for a new credential")
	}
	if c.Audience != v.Audience {
		return nil, refused("credential is for %s", c.Audience)
	}
	from, _ := parseTime(c.ValidFrom)
	until, _ := parseTime(c.ValidUntil)
	if now.Before(from) || !now.Before(until) {
		return nil, refused("credential is not valid now")
	}
	holder, _ := registry.DecodePublicKey(c.Holder)
	msg, err := signingBytes(env.ID, ch)
	if err != nil {
		return nil, err
	}
	sig, err := b64.DecodeString(p.Signature)
	if err != nil || !ed25519.Verify(holder, msg, sig) {
		return nil, refused("holder signature does not verify")
	}
	if c.Status != nil {
		if v.StatusList == nil {
			return nil, refused("credential has a status entry and no status list is available")
		}
		listEnv, err := v.StatusList(env.Issuer, c.Status.List)
		if err != nil {
			return nil, refused("status list: %v", err)
		}
		list, err := DecodeStatusList(listEnv)
		if err != nil {
			return nil, err
		}
		if listEnv.Issuer != env.Issuer || list.List != c.Status.List {
			return nil, refused("status list is not the credential's")
		}
		if err := v.Registry.Verify(listEnv); err != nil {
			return nil, refused("status list signature: %v", err)
		}
		if at, _ := listEnv.IssuedAtTime(); now.Sub(at) > MaxStatusAge {
			return nil, refused("status list is older than %s", MaxStatusAge)
		}
		revoked, err := list.IsRevoked(c.Status.Index)
		if err != nil {
			return nil, err
		}
		if revoked {
			return nil, refused("credential has been revoked")
		}
	}
	return &Verified{Issuer: env.Issuer, Credential: env.ID, Holder: c.Holder, Claims: c.Claims, ValidUntil: until}, nil
}

// StatusList is the payload of credential-status-list/1: one bit per
// credential, set when the credential is revoked. Every credential of a list
// shares it, so fetching the list reveals nothing about which credential is
// being checked.
type StatusList struct {
	List    string `json:"list"`
	Size    int64  `json:"size"`
	Revoked string `json:"revoked"`

	bits []byte
}

// NewStatusList returns a signed status list of the given size with the
// given entries revoked.
func NewStatusList(state protocol.Identity, list string, size int64, revoked []int64) (*record.Envelope, error) {
	if !listPattern.MatchString(list) || size < 1 || size > MaxStatusSize {
		return nil, invalid("status list needs a name and a size of 1 to %d", MaxStatusSize)
	}
	bits := make([]byte, (size+7)/8)
	for _, i := range revoked {
		if i < 0 || i >= size {
			return nil, invalid("index %d is outside the list", i)
		}
		bits[i/8] |= 0x80 >> (i % 8)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(bits)
	zw.Close()
	return state.Message("", StatusListType, &StatusList{List: list, Size: size, Revoked: b64.EncodeToString(buf.Bytes())})
}

// DecodeStatusList returns the validated payload of a status list record.
func DecodeStatusList(env *record.Envelope) (*StatusList, error) {
	var s StatusList
	if err := decode(env, StatusListType, &s); err != nil {
		return nil, err
	}
	if !listPattern.MatchString(s.List) || s.Size < 1 || s.Size > MaxStatusSize {
		return nil, invalid("status list needs a name and a size of 1 to %d", MaxStatusSize)
	}
	raw, err := b64.DecodeString(s.Revoked)
	if err != nil {
		return nil, invalid("revoked must be base64url")
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, invalid("revoked must be gzip")
	}
	want := (s.Size + 7) / 8
	s.bits, err = io.ReadAll(io.LimitReader(zr, want+1))
	if err != nil || int64(len(s.bits)) != want {
		return nil, invalid("revoked must hold %d bytes", want)
	}
	return &s, nil
}

// IsRevoked reports whether the entry at index is revoked.
func (s *StatusList) IsRevoked(index int64) (bool, error) {
	if index < 0 || index >= s.Size {
		return false, invalid("index %d is outside the list", index)
	}
	return s.bits[index/8]&(0x80>>(index%8)) != 0, nil
}

func decode(env *record.Envelope, typ string, v any) error {
	if env.Type != typ {
		return invalid("record type is %q, not %q", env.Type, typ)
	}
	if env.To != "" {
		return invalid("%s records are not addressed", typ)
	}
	dec := json.NewDecoder(bytes.NewReader(env.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("payload: %v", err)
	}
	return nil
}
