// Package network starts a set of instances on local HTTPS servers, each
// with its own key, signed description, attestation from its parent, and its
// own registry. It is for demonstrations and tests.
package network

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"time"

	"github.com/polycentric-commonwealth/foundation/ledger"
	"github.com/polycentric-commonwealth/foundation/protocol"
	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"
)

// Spec describes an instance to start.
type Spec struct {
	Instance string
	Layer    record.Layer
	Name     string
	Parent   string
}

// Node is a running instance.
type Node struct {
	Identity    protocol.Identity
	Description *registry.Description
	Registry    *registry.Registry
	Store       *protocol.MemoryStore
	Receiver    *protocol.Receiver
	Sender      *protocol.Sender
	Log         *ledger.Log
	Witness     *ledger.Witness
	Server      *httptest.Server

	// Extra, if set, serves every path the node does not handle itself.
	Extra http.Handler

	// Signed is the node's signed description and Attestations the
	// attestations its parent issued for it, as served at the well-known
	// paths.
	Signed       *record.Envelope
	Attestations []*record.Envelope
}

// Network is a set of running instances.
type Network struct {
	Nodes map[string]*Node

	// HTTP is a client that trusts every node's server certificate.
	HTTP *http.Client
}

// Close stops every server.
func (n *Network) Close() {
	for _, node := range n.Nodes {
		node.Server.Close()
	}
}

var depth = map[record.Layer]int{record.Commonwealth: 0, record.Region: 1, record.State: 2, record.Locality: 3}

// Start launches the instances. Exactly one must be at the Commonwealth
// layer; it becomes every node's trust anchor.
func Start(specs ...Spec) (*Network, error) {
	net := &Network{Nodes: map[string]*Node{}}
	ok := false
	defer func() {
		if !ok {
			net.Close()
		}
	}()

	// Order parents before children, so attestations can be checked in turn.
	specs = append([]Spec(nil), specs...)
	sort.SliceStable(specs, func(i, j int) bool { return depth[specs[i].Layer] < depth[specs[j].Layer] })

	validFrom := time.Now().UTC().Add(-time.Hour).Truncate(time.Second).Format(time.RFC3339)
	var anchor *registry.Anchor
	pool := x509.NewCertPool()
	var descriptions, attestations []*record.Envelope

	for _, s := range specs {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		node := &Node{
			Identity: protocol.Identity{Instance: s.Instance, Layer: s.Layer, KeyID: "k1", Key: priv},
			Store:    protocol.NewMemoryStore(),
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/"+protocol.InboxPath, func(w http.ResponseWriter, r *http.Request) { node.Receiver.ServeHTTP(w, r) })
		mux.HandleFunc("/"+ledger.WitnessPath, func(w http.ResponseWriter, r *http.Request) { node.Witness.ServeHTTP(w, r) })
		mux.Handle("/ledger/", http.StripPrefix("/ledger", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			node.Log.Handler().ServeHTTP(w, r)
		})))
		mux.HandleFunc("GET "+registry.WellKnownPath, func(w http.ResponseWriter, r *http.Request) {
			data, _ := node.Signed.Marshal()
			w.Header().Set("Content-Type", "application/json")
			w.Write(data)
		})
		mux.HandleFunc("GET "+registry.AttestationsPath, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(append([]*record.Envelope{}, node.Attestations...))
		})
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if node.Extra == nil {
				http.NotFound(w, r)
				return
			}
			node.Extra.ServeHTTP(w, r)
		})
		node.Server = httptest.NewTLSServer(mux)
		net.Nodes[s.Instance] = node
		pool.AddCert(node.Server.Certificate())

		node.Description = &registry.Description{
			Instance:  s.Instance,
			Layer:     s.Layer,
			Name:      s.Name,
			Parent:    s.Parent,
			Endpoints: map[string]string{"base": node.Server.URL + "/"},
			Keys:      []registry.Key{{ID: "k1", PublicKey: registry.EncodePublicKey(pub), ValidFrom: validFrom}},
		}
		d, err := registry.NewDescription(node.Description, "k1", priv)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.Instance, err)
		}
		descriptions = append(descriptions, d)
		node.Signed = d

		if s.Layer == record.Commonwealth {
			if anchor != nil {
				return nil, fmt.Errorf("network: more than one commonwealth instance")
			}
			anchor = &registry.Anchor{Instance: s.Instance, PublicKey: registry.EncodePublicKey(pub)}
			continue
		}
		parent, found := net.Nodes[s.Parent]
		if !found {
			return nil, fmt.Errorf("network: %s's parent %s is not in the network", s.Instance, s.Parent)
		}
		a, err := registry.NewAttestation(parent.Identity.Instance, parent.Identity.Layer, "k1", parent.Identity.Key,
			&registry.Attestation{Subject: s.Instance, SubjectLayer: s.Layer,
				Keys: []registry.AttestedKey{{ID: "k1", PublicKey: registry.EncodePublicKey(pub)}}})
		if err != nil {
			return nil, err
		}
		attestations = append(attestations, a)
		node.Attestations = append(node.Attestations, a)
	}
	if anchor == nil {
		return nil, fmt.Errorf("network: no commonwealth instance")
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
	for _, node := range net.Nodes {
		reg, err := registry.New(*anchor)
		if err != nil {
			return nil, err
		}
		for _, d := range descriptions {
			if err := reg.AddDescription(d); err != nil {
				return nil, err
			}
		}
		for _, a := range attestations {
			if err := reg.AddAttestation(a); err != nil {
				return nil, err
			}
		}
		node.Registry = reg
		node.Receiver = &protocol.Receiver{Self: node.Identity, Registry: reg, Store: node.Store, Handlers: map[string]protocol.Handler{}}
		node.Sender = &protocol.Sender{Self: node.Identity, Registry: reg, HTTP: client}
		node.Log = ledger.NewLog(node.Identity, nil)
		node.Witness = &ledger.Witness{Self: node.Identity, Registry: reg, Store: &ledger.MemoryWitnessStore{}}
	}
	net.HTTP = client
	ok = true
	return net, nil
}

// RevokeAndReplace gives an instance a new key, attested by its parent, and
// publishes a description that revokes its current key from revokedAt. Every
// node's registry receives the attestation and the new description, and the
// node switches to signing with the new key.
func (n *Network) RevokeAndReplace(instance string, revokedAt time.Time) error {
	node, ok := n.Nodes[instance]
	if !ok {
		return fmt.Errorf("network: no instance %s", instance)
	}
	parent, ok := n.Nodes[node.Description.Parent]
	if !ok {
		return fmt.Errorf("network: %s has no parent in the network", instance)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	newID := fmt.Sprintf("k%d", len(node.Description.Keys)+1)
	now := time.Now().UTC().Truncate(time.Second)

	desc := *node.Description
	desc.Keys = append([]registry.Key(nil), node.Description.Keys...)
	for i := range desc.Keys {
		if desc.Keys[i].ID == node.Identity.KeyID {
			desc.Keys[i].RevokedAt = revokedAt.UTC().Format(time.RFC3339)
		}
	}
	desc.Keys = append(desc.Keys, registry.Key{ID: newID, PublicKey: registry.EncodePublicKey(pub), ValidFrom: now.Add(-time.Minute).Format(time.RFC3339)})

	att, err := registry.NewAttestation(parent.Identity.Instance, parent.Identity.Layer, parent.Identity.KeyID, parent.Identity.Key,
		&registry.Attestation{Subject: instance, SubjectLayer: desc.Layer,
			Keys: []registry.AttestedKey{{ID: newID, PublicKey: registry.EncodePublicKey(pub)}}})
	if err != nil {
		return err
	}
	// The new description must be dated after the previous one.
	time.Sleep(1100 * time.Millisecond)
	d, err := registry.NewDescription(&desc, newID, priv)
	if err != nil {
		return err
	}
	for _, other := range n.Nodes {
		if err := other.Registry.AddAttestation(att); err != nil {
			return fmt.Errorf("%s: %w", other.Identity.Instance, err)
		}
		if err := other.Registry.AddDescription(d); err != nil {
			return fmt.Errorf("%s: %w", other.Identity.Instance, err)
		}
	}
	node.Description, node.Signed = &desc, d
	node.Attestations = append(node.Attestations, att)
	node.Identity.KeyID, node.Identity.Key = newID, priv
	node.Receiver.Self, node.Sender.Self, node.Witness.Self = node.Identity, node.Identity, node.Identity
	node.Log.Self = node.Identity
	return nil
}
