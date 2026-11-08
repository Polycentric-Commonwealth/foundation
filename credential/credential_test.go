package credential

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/polycentric-commonwealth/foundation/internal/network"
	"github.com/polycentric-commonwealth/foundation/protocol"
	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"
)

func TestCredential(t *testing.T) {
	net, err := network.Start(
		network.Spec{Instance: "commonwealth.example", Layer: record.Commonwealth, Name: "Commonwealth"},
		network.Spec{Instance: "region.example", Layer: record.Region, Name: "Region", Parent: "commonwealth.example"},
		network.Spec{Instance: "state.example", Layer: record.State, Name: "State", Parent: "region.example"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer net.Close()
	state := net.Nodes["state.example"].Identity
	cw := net.Nodes["commonwealth.example"]

	// One key per audience: the resident's wallet makes a new key for the
	// Commonwealth's sortition office and another for the Region.
	pubC, privC, _ := ed25519.GenerateKey(rand.Reader)
	pubR, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Truncate(time.Second)
	issue := func(audience string, pub ed25519.PublicKey, status *Status) *record.Envelope {
		t.Helper()
		env, err := Issue(state, &Credential{
			Holder: registry.EncodePublicKey(pub), Audience: audience,
			Claims:    []string{ClaimResident, ClaimAdult},
			ValidFrom: now.Add(-time.Hour).Format(time.RFC3339), ValidUntil: now.Add(90 * 24 * time.Hour).Format(time.RFC3339),
			Status: status,
		})
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	credC := issue("commonwealth.example", pubC, &Status{List: "2026", Index: 7})
	credR := issue("region.example", pubR, nil)
	if credC.ID == credR.ID {
		t.Fatal("credentials share an id")
	}

	lists := map[string]*record.Envelope{}
	publish := func(revoked ...int64) {
		env, err := NewStatusList(state, "2026", 1000, revoked)
		if err != nil {
			t.Fatal(err)
		}
		lists["state.example/2026"] = env
	}
	publish(3)
	v := &Verifier{Audience: "commonwealth.example", Registry: cw.Registry,
		StatusList: func(issuer, list string) (*record.Envelope, error) {
			if env, ok := lists[issuer+"/"+list]; ok {
				return env, nil
			}
			return nil, errors.New("not found")
		}}

	ch, _ := NewChallenge("commonwealth.example")
	p, err := Present(credC, privC, ch)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Verify(p, ch)
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != "state.example" || len(got.Claims) != 2 || got.Claims[0] != ClaimAdult {
		t.Errorf("verified = %+v", got)
	}

	refusedCases := map[string]func() (*Presentation, Challenge){
		"another challenge": func() (*Presentation, Challenge) {
			other, _ := NewChallenge("commonwealth.example")
			return p, other
		},
		"challenge for another audience": func() (*Presentation, Challenge) {
			c := ch
			c.Audience = "region.example"
			return p, c
		},
		"expired challenge": func() (*Presentation, Challenge) {
			c := ch
			c.IssuedAt = now.Add(-time.Hour).Format(time.RFC3339)
			q, _ := Present(credC, privC, c)
			return q, c
		},
		"credential for another audience": func() (*Presentation, Challenge) {
			q := *p
			q.Credential = credR
			return &q, ch
		},
		"tampered credential": func() (*Presentation, Challenge) {
			e := *credC
			e.Payload = []byte(`{"holder":"` + registry.EncodePublicKey(pubC) + `","audience":"commonwealth.example","claims":["adult","dividend-eligible","resident"],"valid_from":"` +
				now.Add(-time.Hour).Format(time.RFC3339) + `","valid_until":"` + now.Add(time.Hour).Format(time.RFC3339) + `"}`)
			q, _ := Present(&e, privC, ch)
			return q, ch
		},
		"wrong holder signature": func() (*Presentation, Challenge) {
			q := *p
			q.Signature = p.Signature[:10] + "AAAA" + p.Signature[14:]
			return &q, ch
		},
	}
	for name, mk := range refusedCases {
		q, c := mk()
		if q == nil {
			t.Errorf("%s: could not build presentation", name)
			continue
		}
		if _, err := v.Verify(q, c); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: err = %v, want ErrRefused", name, err)
		}
	}

	// Revoking entry 7 refuses the credential; a stale list is refused too.
	publish(3, 7)
	if _, err := v.Verify(p, ch); !errors.Is(err, ErrRefused) {
		t.Errorf("revoked: err = %v", err)
	}
	publish()
	v.Now = func() time.Time { return time.Now().Add(25 * time.Hour) }
	ch2 := Challenge{Audience: ch.Audience, Nonce: ch.Nonce, IssuedAt: v.Now().UTC().Format(time.RFC3339)}
	p2, _ := Present(credC, privC, ch2)
	if _, err := v.Verify(p2, ch2); !errors.Is(err, ErrRefused) {
		t.Errorf("stale status list: err = %v", err)
	}

	// Only States issue, and only known claims.
	if _, err := Issue(cw.Identity, &Credential{}); err == nil {
		t.Error("Commonwealth issued a credential")
	}
	if _, err := Issue(state, &Credential{Holder: registry.EncodePublicKey(pubC), Audience: "commonwealth.example",
		Claims: []string{"citizen"}, ValidFrom: credC.IssuedAt, ValidUntil: now.Add(time.Hour).Format(time.RFC3339)}); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown claim: err = %v", err)
	}
	// The holder cannot present with another key.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Present(credC, other, ch); err == nil {
		t.Error("presented with the wrong key")
	}
}

func TestStatusList(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	state := protocol.Identity{Instance: "state.example", Layer: record.State, KeyID: "k1", Key: priv}
	env, err := NewStatusList(state, "a", 20, []int64{0, 9, 19})
	if err != nil {
		t.Fatal(err)
	}
	l, err := DecodeStatusList(env)
	if err != nil {
		t.Fatal(err)
	}
	for i := int64(0); i < 20; i++ {
		got, _ := l.IsRevoked(i)
		if want := i == 0 || i == 9 || i == 19; got != want {
			t.Errorf("entry %d revoked = %v", i, got)
		}
	}
	if _, err := l.IsRevoked(20); err == nil {
		t.Error("index past the end accepted")
	}
	if _, err := NewStatusList(state, "a", 20, []int64{20}); err == nil {
		t.Error("revoked index past the end accepted")
	}
}
