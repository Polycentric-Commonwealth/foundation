package record

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type countPayload struct {
	EligibleAdults int64 `json:"eligible_adults"`
	Residents      int64 `json:"residents"`
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signed(t *testing.T, priv ed25519.PrivateKey) *Envelope {
	t.Helper()
	e, err := New("state.example", "2026-1", State, "eligibility-count/1",
		countPayload{EligibleAdults: 4120533, Residents: 5302114})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestSignAndVerify(t *testing.T) {
	pub, priv := newKey(t)
	e := signed(t, priv)
	if err := e.Verify(pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestRoundTripThroughJSON(t *testing.T) {
	pub, priv := newKey(t)
	data, err := signed(t, priv).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	e, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := e.Verify(pub); err != nil {
		t.Fatalf("Verify after round trip: %v", err)
	}
}

func TestVerifyIgnoresFormatting(t *testing.T) {
	// The signature covers the canonical form, so the same record with
	// different whitespace and key order must still verify.
	pub, priv := newKey(t)
	e := signed(t, priv)
	reordered := `{"signature":"` + e.Signature + `","payload":{"residents":5302114,"eligible_adults":4120533},` +
		`"issued_at":"` + e.IssuedAt + `","layer":"state","key":"2026-1","issuer":"state.example",` +
		`"type":"eligibility-count/1","id":"` + e.ID + `","spec":"pc-record/0.1"}`
	p, err := Parse([]byte(reordered))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := p.Verify(pub); err != nil {
		t.Fatalf("Verify of reformatted record: %v", err)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	pub, priv := newKey(t)
	tamper := map[string]func(e *Envelope){
		"payload":    func(e *Envelope) { e.Payload = json.RawMessage(`{"eligible_adults":4120534,"residents":5302114}`) },
		"issuer":     func(e *Envelope) { e.Issuer = "state.other" },
		"key":        func(e *Envelope) { e.Key = "2026-2" },
		"layer":      func(e *Envelope) { e.Layer = Region },
		"type":       func(e *Envelope) { e.Type = "eligibility-count/2" },
		"issued_at":  func(e *Envelope) { e.IssuedAt = "2030-01-01T00:00:00Z" },
		"supersedes": func(e *Envelope) { e.Supersedes = e.ID },
	}
	for field, change := range tamper {
		t.Run(field, func(t *testing.T) {
			e := signed(t, priv)
			change(e)
			if err := e.Verify(pub); !errors.Is(err, ErrSignature) {
				t.Errorf("Verify after changing %s = %v, want ErrSignature", field, err)
			}
		})
	}
}

func TestWrongKeyFails(t *testing.T) {
	_, priv := newKey(t)
	otherPub, _ := newKey(t)
	if err := signed(t, priv).Verify(otherPub); !errors.Is(err, ErrSignature) {
		t.Errorf("Verify with wrong key = %v, want ErrSignature", err)
	}
}

func TestUnsignedAndMalformedSignatures(t *testing.T) {
	pub, priv := newKey(t)
	e := signed(t, priv)
	for _, sig := range []string{"", "not base64!", "AAAA"} {
		e.Signature = sig
		if err := e.Verify(pub); !errors.Is(err, ErrSignature) {
			t.Errorf("Verify with signature %q = %v, want ErrSignature", sig, err)
		}
	}
}

type mapResolver map[string]ed25519.PublicKey

func (m mapResolver) PublicKey(issuer, key string) (ed25519.PublicKey, error) {
	pub, ok := m[issuer+"/"+key]
	if !ok {
		return nil, errors.New("unknown key")
	}
	return pub, nil
}

func TestVerifyWith(t *testing.T) {
	pub, priv := newKey(t)
	e := signed(t, priv)
	if err := e.VerifyWith(mapResolver{"state.example/2026-1": pub}); err != nil {
		t.Errorf("VerifyWith known key: %v", err)
	}
	if err := e.VerifyWith(mapResolver{}); !errors.Is(err, ErrSignature) {
		t.Errorf("VerifyWith unknown key = %v, want ErrSignature", err)
	}
}

func TestNewRejectsInvalidFields(t *testing.T) {
	ok := countPayload{1, 2}
	tests := []struct {
		name                    string
		issuer, key, layer, typ string
		payload                 any
	}{
		{"empty issuer", "", "k", "state", "t/1", ok},
		{"issuer with space", "a b", "k", "state", "t/1", ok},
		{"empty key", "i", "", "state", "t/1", ok},
		{"unknown layer", "i", "k", "planet", "t/1", ok},
		{"type without version", "i", "k", "state", "count", ok},
		{"type with uppercase", "i", "k", "state", "Count/1", ok},
		{"type version zero", "i", "k", "state", "count/0", ok},
		{"payload not an object", "i", "k", "state", "t/1", []int{1}},
		{"payload with fraction", "i", "k", "state", "t/1", map[string]float64{"rate": 0.5}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.issuer, tt.key, Layer(tt.layer), tt.typ, tt.payload)
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("New error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	_, priv := newKey(t)
	good, err := signed(t, priv).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	s := string(good)
	tests := map[string]string{
		"unknown field":     strings.Replace(s, `"spec"`, `"extra": 1, "spec"`, 1),
		"duplicate field":   strings.Replace(s, `"spec"`, `"layer": "state", "spec"`, 1),
		"wrong spec":        strings.Replace(s, `pc-record/0.1`, `pc-record/9.9`, 1),
		"fraction anywhere": strings.Replace(s, `4120533`, `4120533.5`, 1),
		"not UTC":           strings.Replace(s, `Z"`, `+01:00"`, 1),
		"not JSON":          `{`,
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(in)); !errors.Is(err, ErrInvalid) {
				t.Errorf("Parse error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestNewUUIDv7(t *testing.T) {
	when := time.UnixMilli(1762576200000)
	a, err := newUUIDv7(when)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newUUIDv7(when)
	if a == b {
		t.Error("two ids with the same timestamp were equal")
	}
	for _, id := range []string{a, b} {
		if !uuidV7Pattern.MatchString(id) {
			t.Errorf("id %q is not a UUID version 7", id)
		}
	}
	// The first 48 bits are the millisecond timestamp (0x019a61ba7140).
	if want := "019a61ba-7140-"; !strings.HasPrefix(a, want) {
		t.Errorf("id %q does not start with timestamp %s", a, want)
	}
	later, _ := newUUIDv7(when.Add(time.Millisecond))
	if later <= a {
		t.Errorf("later id %q does not sort after %q", later, a)
	}
}
