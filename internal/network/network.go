// Package network starts a set of instances on local HTTPS servers, each
// with its own key, signed description, attestation from its parent, and its
// own registry. It is for demonstrations and tests.
package network

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"time"

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
	Server      *httptest.Server
}

// Network is a set of running instances.
type Network struct {
	Nodes map[string]*Node
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
		node.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/"+protocol.InboxPath {
				http.NotFound(w, r)
				return
			}
			node.Receiver.ServeHTTP(w, r)
		}))
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
	}
	ok = true
	return net, nil
}
