package registry_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/polycentric-commonwealth/foundation/internal/network"
	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"
)

func TestDiscover(t *testing.T) {
	net, err := network.Start(
		network.Spec{Instance: "commonwealth.example", Layer: record.Commonwealth, Name: "Commonwealth"},
		network.Spec{Instance: "region.example", Layer: record.Region, Name: "Region", Parent: "commonwealth.example"},
		network.Spec{Instance: "state.example", Layer: record.State, Name: "State", Parent: "region.example"},
		network.Spec{Instance: "town.state.example", Layer: record.Locality, Name: "Town", Parent: "state.example"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer net.Close()

	cw := net.Nodes["commonwealth.example"]
	cwKey, _ := cw.Description.Key("k1")
	reg, err := registry.New(registry.Anchor{Instance: "commonwealth.example", PublicKey: cwKey.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	f := &registry.Fetcher{Registry: reg, HTTP: net.HTTP, Origin: func(instance string) string {
		if n, ok := net.Nodes[instance]; ok {
			return n.Server.URL
		}
		return "https://" + instance
	}}

	// Discovering the locality walks up to the anchor and back down.
	if err := f.Discover(context.Background(), "town.state.example"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"commonwealth.example", "region.example", "state.example", "town.state.example"} {
		if _, ok := reg.Description(id); !ok {
			t.Errorf("%s was not discovered", id)
		}
	}
	town := net.Nodes["town.state.example"]
	env, err := town.Identity.Message("", "eligibility-count/1", map[string]any{"period": "2027-01"})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Verify(env); err != nil {
		t.Errorf("record from a discovered instance does not verify: %v", err)
	}

	// Discovering again is a refresh, and picks up a key rotation.
	if err := f.Discover(context.Background(), "town.state.example"); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := net.RevokeAndReplace("state.example", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := f.Discover(context.Background(), "state.example"); err != nil {
		t.Fatalf("refresh after rotation: %v", err)
	}
	if _, revoked := reg.RevokedAt("state.example", "k1"); !revoked {
		t.Error("rotation was not picked up")
	}

	// An attestation from someone other than the parent is not enough.
	impostor := net.Nodes["state.example"]
	impostor.Attestations = nil
	fresh, _ := registry.New(registry.Anchor{Instance: "commonwealth.example", PublicKey: cwKey.PublicKey})
	f.Registry = fresh
	if err := f.Discover(context.Background(), "state.example"); err == nil || !strings.Contains(err.Error(), "state.example") {
		t.Errorf("discovered a State with no attestation: %v", err)
	}
}
