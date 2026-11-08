package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/polycentric-commonwealth/foundation/record"
)

// inst is a test instance with its private keys and current description.
type inst struct {
	desc *Description
	priv map[string]ed25519.PrivateKey
}

const keysFrom = "2026-01-01T00:00:00Z"

func newInst(t *testing.T, id string, layer record.Layer, parent string, keyIDs ...string) *inst {
	t.Helper()
	i := &inst{
		desc: &Description{
			Instance:  id,
			Layer:     layer,
			Name:      "Test " + id,
			Parent:    parent,
			Endpoints: map[string]string{"base": "https://" + id + "/pc/"},
		},
		priv: map[string]ed25519.PrivateKey{},
	}
	for _, k := range keyIDs {
		i.addKey(t, k, keysFrom)
	}
	return i
}

func (i *inst) addKey(t *testing.T, id, from string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	i.priv[id] = priv
	i.desc.Keys = append(i.desc.Keys, Key{ID: id, PublicKey: EncodePublicKey(pub), ValidFrom: from})
}

func (i *inst) key(id string) *Key {
	for n := range i.desc.Keys {
		if i.desc.Keys[n].ID == id {
			return &i.desc.Keys[n]
		}
	}
	return nil
}

func (i *inst) pub(id string) string { return i.key(id).PublicKey }

func (i *inst) anchor(keyID string) Anchor {
	return Anchor{Instance: i.desc.Instance, PublicKey: i.pub(keyID)}
}

// at re-dates an envelope and signs it again.
func at(t *testing.T, env *record.Envelope, priv ed25519.PrivateKey, when string) *record.Envelope {
	t.Helper()
	env.IssuedAt = when
	if err := env.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return env
}

// describe returns the instance's current description, signed with keyID
// and dated when. It copies the description so later edits do not alter it.
func (i *inst) describe(t *testing.T, keyID, when string) *record.Envelope {
	t.Helper()
	d := *i.desc
	d.Keys = append([]Key(nil), i.desc.Keys...)
	env, err := record.New(d.Instance, keyID, d.Layer, DescriptionType, &d)
	if err != nil {
		t.Fatal(err)
	}
	return at(t, env, i.priv[keyID], when)
}

// attest returns an attestation by i of child's listed keys.
func (i *inst) attest(t *testing.T, keyID string, child *inst, when string, childKeys ...string) *record.Envelope {
	t.Helper()
	a := &Attestation{Subject: child.desc.Instance, SubjectLayer: child.desc.Layer}
	for _, k := range childKeys {
		a.Keys = append(a.Keys, AttestedKey{ID: k, PublicKey: child.pub(k)})
	}
	env, err := NewAttestation(i.desc.Instance, i.desc.Layer, keyID, i.priv[keyID], a)
	if err != nil {
		t.Fatal(err)
	}
	return at(t, env, i.priv[keyID], when)
}

// sign returns an ordinary record from i, signed with keyID at when.
func (i *inst) sign(t *testing.T, keyID, when string) *record.Envelope {
	t.Helper()
	env, err := record.New(i.desc.Instance, keyID, i.desc.Layer, "eligibility-count/1", map[string]int{"residents": 1000})
	if err != nil {
		t.Fatal(err)
	}
	return at(t, env, i.priv[keyID], when)
}

func mustAdd(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// world is a Commonwealth, a State under it and a Locality under the State,
// with every description and attestation loaded.
type world struct {
	r            *Registry
	cw, st, city *inst
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{
		cw:   newInst(t, "commonwealth.example", record.Commonwealth, "", "2026-1"),
		st:   newInst(t, "state.example", record.State, "commonwealth.example", "2026-1"),
		city: newInst(t, "city.state.example", record.Locality, "state.example", "2026-1"),
	}
	r, err := New(w.cw.anchor("2026-1"))
	mustAdd(t, err)
	w.r = r
	for _, i := range []*inst{w.cw, w.st, w.city} {
		mustAdd(t, r.AddDescription(i.describe(t, "2026-1", "2026-02-01T00:00:00Z")))
	}
	mustAdd(t, r.AddAttestation(w.cw.attest(t, "2026-1", w.st, "2026-02-02T00:00:00Z", "2026-1")))
	mustAdd(t, r.AddAttestation(w.st.attest(t, "2026-1", w.city, "2026-02-03T00:00:00Z", "2026-1")))
	return w
}

func TestTrustChain(t *testing.T) {
	w := newWorld(t)
	for _, i := range []*inst{w.cw, w.st, w.city} {
		if err := w.r.Verify(i.sign(t, "2026-1", "2026-03-01T00:00:00Z")); err != nil {
			t.Errorf("record from %s: %v", i.desc.Instance, err)
		}
	}
}

func TestUnattestedInstanceIsUntrusted(t *testing.T) {
	w := newWorld(t)
	other := newInst(t, "other.state.example", record.Locality, "state.example", "2026-1")
	mustAdd(t, w.r.AddDescription(other.describe(t, "2026-1", "2026-02-01T00:00:00Z")))
	err := w.r.Verify(other.sign(t, "2026-1", "2026-03-01T00:00:00Z"))
	if !errors.Is(err, ErrUntrusted) {
		t.Errorf("unattested locality: got %v, want ErrUntrusted", err)
	}
}

func TestAnchorPinsKeyNotName(t *testing.T) {
	real := newInst(t, "commonwealth.example", record.Commonwealth, "", "2026-1")
	impostor := newInst(t, "commonwealth.example", record.Commonwealth, "", "2026-1")
	r, err := New(real.anchor("2026-1"))
	mustAdd(t, err)
	mustAdd(t, r.AddDescription(impostor.describe(t, "2026-1", "2026-02-01T00:00:00Z")))
	if err := r.Verify(impostor.sign(t, "2026-1", "2026-03-01T00:00:00Z")); !errors.Is(err, ErrUntrusted) {
		t.Errorf("impostor anchor: got %v, want ErrUntrusted", err)
	}
}

func TestNoAnchorsTrustsNothing(t *testing.T) {
	cw := newInst(t, "commonwealth.example", record.Commonwealth, "", "2026-1")
	r, err := New()
	mustAdd(t, err)
	mustAdd(t, r.AddDescription(cw.describe(t, "2026-1", "2026-02-01T00:00:00Z")))
	if err := r.Verify(cw.sign(t, "2026-1", "2026-03-01T00:00:00Z")); !errors.Is(err, ErrUntrusted) {
		t.Errorf("got %v, want ErrUntrusted", err)
	}
}

func TestUnknownInstanceAndKey(t *testing.T) {
	w := newWorld(t)
	stranger := newInst(t, "stranger.example", record.State, "commonwealth.example", "2026-1")
	if err := w.r.Verify(stranger.sign(t, "2026-1", "2026-03-01T00:00:00Z")); !errors.Is(err, ErrUnknownInstance) {
		t.Errorf("unknown instance: got %v", err)
	}
	w.st.addKey(t, "unlisted", keysFrom)
	if err := w.r.Verify(w.st.sign(t, "unlisted", "2026-03-01T00:00:00Z")); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("unknown key: got %v", err)
	}
}

func TestAttestationMustComeFromTrustedParent(t *testing.T) {
	w := newWorld(t)

	// A sibling State, itself trusted, tries to vouch for another State's city.
	other := newInst(t, "other.example", record.State, "commonwealth.example", "2026-1")
	mustAdd(t, w.r.AddDescription(other.describe(t, "2026-1", "2026-02-01T00:00:00Z")))
	mustAdd(t, w.r.AddAttestation(w.cw.attest(t, "2026-1", other, "2026-02-02T00:00:00Z", "2026-1")))
	if err := w.r.AddAttestation(other.attest(t, "2026-1", w.city, "2026-02-04T00:00:00Z", "2026-1")); !errors.Is(err, ErrParent) {
		t.Errorf("attestation from non-parent: got %v, want ErrParent", err)
	}

	// An untrusted State cannot vouch for anyone.
	rogue := newInst(t, "rogue.example", record.State, "commonwealth.example", "2026-1")
	mustAdd(t, w.r.AddDescription(rogue.describe(t, "2026-1", "2026-02-01T00:00:00Z")))
	town := newInst(t, "town.rogue.example", record.Locality, "rogue.example", "2026-1")
	if err := w.r.AddAttestation(rogue.attest(t, "2026-1", town, "2026-02-04T00:00:00Z", "2026-1")); !errors.Is(err, ErrUntrusted) {
		t.Errorf("attestation from untrusted issuer: got %v, want ErrUntrusted", err)
	}
}

func TestAttestationLayerRules(t *testing.T) {
	cw := newInst(t, "commonwealth.example", record.Commonwealth, "", "2026-1")
	city := newInst(t, "city.state.example", record.Locality, "state.example", "2026-1")
	a := &Attestation{Subject: city.desc.Instance, SubjectLayer: record.Locality,
		Keys: []AttestedKey{{ID: "2026-1", PublicKey: city.pub("2026-1")}}}
	if _, err := NewAttestation(cw.desc.Instance, record.Commonwealth, "2026-1", cw.priv["2026-1"], a); !errors.Is(err, ErrInvalid) {
		t.Errorf("commonwealth attesting a locality: got %v, want ErrInvalid", err)
	}
}

func TestAttestationBeforeDescription(t *testing.T) {
	w := newWorld(t)
	late := newInst(t, "late.example", record.State, "commonwealth.example", "2026-1")
	mustAdd(t, w.r.AddAttestation(w.cw.attest(t, "2026-1", late, "2026-02-02T00:00:00Z", "2026-1")))
	mustAdd(t, w.r.AddDescription(late.describe(t, "2026-1", "2026-02-05T00:00:00Z")))
	if err := w.r.Verify(late.sign(t, "2026-1", "2026-03-01T00:00:00Z")); err != nil {
		t.Errorf("record after late description: %v", err)
	}

	// A description naming a different parent than the attesting one is refused.
	confused := newInst(t, "confused.example", record.State, "elsewhere.example", "2026-1")
	mustAdd(t, w.r.AddAttestation(w.cw.attest(t, "2026-1", confused, "2026-02-02T00:00:00Z", "2026-1")))
	if err := w.r.AddDescription(confused.describe(t, "2026-1", "2026-02-05T00:00:00Z")); !errors.Is(err, ErrParent) {
		t.Errorf("parent mismatch: got %v, want ErrParent", err)
	}
}

func TestRotation(t *testing.T) {
	w := newWorld(t)
	w.st.key("2026-1").ValidUntil = "2027-01-01T00:00:00Z"
	w.st.addKey(t, "2027-1", "2026-12-01T00:00:00Z")
	mustAdd(t, w.r.AddDescription(w.st.describe(t, "2026-1", "2026-06-01T00:00:00Z")))

	tests := []struct {
		key, when string
		want      error
	}{
		{"2027-1", "2027-02-01T00:00:00Z", nil},
		{"2026-1", "2026-12-15T00:00:00Z", nil},
		{"2026-1", "2027-02-01T00:00:00Z", ErrKeyNotValid},
		{"2027-1", "2026-11-01T00:00:00Z", ErrKeyNotValid},
	}
	for _, tt := range tests {
		err := w.r.Verify(w.st.sign(t, tt.key, tt.when))
		if !errors.Is(err, tt.want) && !(tt.want == nil && err == nil) {
			t.Errorf("key %s at %s: got %v, want %v", tt.key, tt.when, err, tt.want)
		}
	}
}

func TestRevocationKeepsEarlierRecordsValid(t *testing.T) {
	w := newWorld(t)
	// A backup key, attested from the start.
	w.st.addKey(t, "backup", keysFrom)
	mustAdd(t, w.r.AddDescription(w.st.describe(t, "2026-1", "2026-02-10T00:00:00Z")))
	mustAdd(t, w.r.AddAttestation(w.cw.attest(t, "2026-1", w.st, "2026-02-11T00:00:00Z", "2026-1", "backup")))

	before := w.st.sign(t, "2026-1", "2026-04-01T00:00:00Z")
	after := w.st.sign(t, "2026-1", "2026-05-03T00:00:00Z")

	w.st.key("2026-1").RevokedAt = "2026-05-01T00:00:00Z"
	mustAdd(t, w.r.AddDescription(w.st.describe(t, "backup", "2026-05-02T00:00:00Z")))

	if err := w.r.Verify(before); err != nil {
		t.Errorf("record signed before revocation: %v", err)
	}
	if err := w.r.Verify(after); !errors.Is(err, ErrKeyNotValid) {
		t.Errorf("record signed after revocation: got %v, want ErrKeyNotValid", err)
	}
}

func TestRecoveryThroughParent(t *testing.T) {
	w := newWorld(t)
	// Every key is lost; the parent attests a replacement.
	w.st.key("2026-1").RevokedAt = "2026-06-01T00:00:00Z"
	w.st.addKey(t, "2026-r", "2026-06-01T00:00:00Z")
	mustAdd(t, w.r.AddAttestation(w.cw.attest(t, "2026-1", w.st, "2026-06-02T00:00:00Z", "2026-r")))
	mustAdd(t, w.r.AddDescription(w.st.describe(t, "2026-r", "2026-06-03T00:00:00Z")))
	if err := w.r.Verify(w.st.sign(t, "2026-r", "2026-07-01T00:00:00Z")); err != nil {
		t.Errorf("record with recovered key: %v", err)
	}
}

func TestContinuityViolations(t *testing.T) {
	tests := map[string]struct {
		change  func(t *testing.T, w *world) *record.Envelope
		wantErr error
	}{
		"not newer": {func(t *testing.T, w *world) *record.Envelope {
			return w.st.describe(t, "2026-1", "2026-02-01T00:00:00Z")
		}, ErrStale},
		"signed by an unattested new key": {func(t *testing.T, w *world) *record.Envelope {
			w.st.addKey(t, "hijack", keysFrom)
			return w.st.describe(t, "hijack", "2026-06-01T00:00:00Z")
		}, ErrContinuity},
		"key removed": {func(t *testing.T, w *world) *record.Envelope {
			w.st.addKey(t, "2027-1", keysFrom)
			w.st.desc.Keys = w.st.desc.Keys[1:]
			return w.st.describe(t, "2027-1", "2026-06-01T00:00:00Z")
		}, ErrContinuity},
		"public key swapped": {func(t *testing.T, w *world) *record.Envelope {
			old := w.st.priv["2026-1"]
			w.st.desc.Keys = nil
			w.st.addKey(t, "2026-1", keysFrom)
			env := w.st.describe(t, "2026-1", "2026-06-01T00:00:00Z")
			w.st.priv["2026-1"] = old
			return env
		}, ErrContinuity},
		"parent changed": {func(t *testing.T, w *world) *record.Envelope {
			w.st.desc.Parent = "elsewhere.example"
			return w.st.describe(t, "2026-1", "2026-06-01T00:00:00Z")
		}, ErrContinuity},
		"validity extended": {func(t *testing.T, w *world) *record.Envelope {
			w.st.addKey(t, "2026-2", keysFrom)
			w.st.key("2026-1").ValidUntil = "2026-12-01T00:00:00Z"
			mustAdd(t, w.r.AddDescription(w.st.describe(t, "2026-1", "2026-06-01T00:00:00Z")))
			w.st.key("2026-1").ValidUntil = "2030-01-01T00:00:00Z"
			return w.st.describe(t, "2026-2", "2026-07-01T00:00:00Z")
		}, ErrContinuity},
		"revocation withdrawn": {func(t *testing.T, w *world) *record.Envelope {
			w.st.addKey(t, "2026-2", keysFrom)
			w.st.key("2026-1").RevokedAt = "2026-06-01T00:00:00Z"
			mustAdd(t, w.r.AddDescription(w.st.describe(t, "2026-1", "2026-05-01T00:00:00Z")))
			w.st.key("2026-1").RevokedAt = ""
			return w.st.describe(t, "2026-2", "2026-07-01T00:00:00Z")
		}, ErrContinuity},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			env := tt.change(t, w)
			if err := w.r.AddDescription(env); !errors.Is(err, tt.wantErr) {
				t.Errorf("got %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseDescriptionChecksSelfSignature(t *testing.T) {
	st := newInst(t, "state.example", record.State, "commonwealth.example", "2026-1")

	tampered := st.describe(t, "2026-1", "2026-02-01T00:00:00Z")
	tampered.Payload = json.RawMessage(`{"instance":"state.example","layer":"state","name":"Renamed","parent":"commonwealth.example","endpoints":{"base":"https://state.example/pc/"},"keys":[{"id":"2026-1","public_key":"` + st.pub("2026-1") + `","valid_from":"` + keysFrom + `"}]}`)
	if _, err := ParseDescription(tampered); !errors.Is(err, record.ErrSignature) {
		t.Errorf("tampered description: got %v, want record.ErrSignature", err)
	}

	unlisted := st.describe(t, "2026-1", "2026-02-01T00:00:00Z")
	unlisted.Key = "other"
	if _, err := ParseDescription(unlisted); !errors.Is(err, ErrInvalid) {
		t.Errorf("signing key not listed: got %v, want ErrInvalid", err)
	}

	early := st.describe(t, "2026-1", "2025-06-01T00:00:00Z")
	if _, err := ParseDescription(early); !errors.Is(err, ErrKeyNotValid) {
		t.Errorf("signed before key was valid: got %v, want ErrKeyNotValid", err)
	}
}

func TestDescriptionValidation(t *testing.T) {
	tests := map[string]func(d *Description){
		"commonwealth with parent": func(d *Description) { d.Layer = record.Commonwealth },
		"state without parent":     func(d *Description) { d.Parent = "" },
		"own parent":               func(d *Description) { d.Parent = d.Instance },
		"bad instance id":          func(d *Description) { d.Instance = "State" },
		"empty name":               func(d *Description) { d.Name = "" },
		"no base endpoint":         func(d *Description) { d.Endpoints = map[string]string{"api": "https://x.example/"} },
		"http endpoint":            func(d *Description) { d.Endpoints["base"] = "http://state.example/" },
		"no keys":                  func(d *Description) { d.Keys = nil },
		"duplicate key ids":        func(d *Description) { d.Keys = append(d.Keys, d.Keys[0]) },
		"bad public key":           func(d *Description) { d.Keys[0].PublicKey = "rsa:abc" },
		"local time":               func(d *Description) { d.Keys[0].ValidFrom = "2026-01-01T00:00:00+01:00" },
		"until before from":        func(d *Description) { d.Keys[0].ValidUntil = "2025-01-01T00:00:00Z" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			st := newInst(t, "state.example", record.State, "commonwealth.example", "2026-1")
			change(st.desc)
			if err := st.desc.Validate(); !errors.Is(err, ErrInvalid) {
				t.Errorf("got %v, want ErrInvalid", err)
			}
		})
	}

	ok := newInst(t, "state.example", record.State, "commonwealth.example", "2026-1")
	if err := ok.desc.Validate(); err != nil {
		t.Errorf("valid description rejected: %v", err)
	}
	if _, err := NewDescription(ok.desc, "2026-1", ok.priv["2026-1"]); err != nil {
		t.Errorf("NewDescription: %v", err)
	}
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := NewDescription(ok.desc, "2026-1", wrong); !errors.Is(err, ErrInvalid) {
		t.Errorf("NewDescription with mismatched private key: got %v, want ErrInvalid", err)
	}
}

func TestKeyValidAt(t *testing.T) {
	k := Key{ValidFrom: "2026-01-01T00:00:00Z", ValidUntil: "2027-01-01T00:00:00Z", RevokedAt: "2026-07-01T00:00:00Z"}
	tests := map[string]bool{
		"2025-12-31T23:59:59Z": false,
		"2026-01-01T00:00:00Z": true,
		"2026-06-30T23:59:59Z": true,
		"2026-07-01T00:00:00Z": false,
		"2026-12-01T00:00:00Z": false,
	}
	for ts, want := range tests {
		when, _ := time.Parse(time.RFC3339, ts)
		if got := k.ValidAt(when); got != want {
			t.Errorf("ValidAt(%s) = %v, want %v", ts, got, want)
		}
	}
}

func TestNewRejectsBadAnchors(t *testing.T) {
	if _, err := New(Anchor{Instance: "nodot", PublicKey: "ed25519:x"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad anchor: got %v, want ErrInvalid", err)
	}
}
