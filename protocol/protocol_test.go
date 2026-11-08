package protocol_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/polycentric-commonwealth/foundation/internal/network"
	"github.com/polycentric-commonwealth/foundation/protocol"
	"github.com/polycentric-commonwealth/foundation/record"
)

const (
	cwID = "commonwealth.example"
	stID = "state.example"
	s2ID = "other.example"
)

func start(t *testing.T) (*network.Network, *network.Node, *network.Node) {
	t.Helper()
	net, err := network.Start(
		network.Spec{Instance: cwID, Layer: record.Commonwealth, Name: "Commonwealth"},
		network.Spec{Instance: stID, Layer: record.State, Name: "State", Parent: cwID},
		network.Spec{Instance: s2ID, Layer: record.State, Name: "Other State", Parent: cwID},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(net.Close)
	cw, st := net.Nodes[cwID], net.Nodes[stID]
	cw.Receiver.Handlers["eligibility-count/1"] = func(context.Context, *record.Envelope) error { return nil }
	return net, cw, st
}

var count = map[string]any{"period": "2027-01", "residents": 10, "adults": 8, "dividend_recipients": 10}

func TestAcceptedThenDuplicate(t *testing.T) {
	_, _, st := start(t)
	env, err := st.Identity.Message(cwID, "eligibility-count/1", count)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := st.Sender.Send(context.Background(), env)
	if err != nil || rc.Status != protocol.StatusAccepted {
		t.Fatalf("first delivery: %+v, %v", rc, err)
	}
	if rc.Envelope == nil || rc.Envelope.Issuer != cwID {
		t.Errorf("receipt envelope not kept: %+v", rc.Envelope)
	}
	rc, err = st.Sender.Send(context.Background(), env)
	if err != nil || rc.Status != protocol.StatusDuplicate {
		t.Fatalf("second delivery: %+v, %v", rc, err)
	}
}

func wantRejected(t *testing.T, err error, reason string) {
	t.Helper()
	rc, ok := protocol.IsRejected(err)
	if !ok {
		t.Fatalf("got %v, want a rejection with reason %s", err, reason)
	}
	if rc.Reason != reason {
		t.Errorf("reason = %s (%s), want %s", rc.Reason, rc.Detail, reason)
	}
	if !errors.Is(err, protocol.ErrRejected) {
		t.Errorf("error does not match ErrRejected")
	}
}

func TestTypeNotAllowedBetweenLayers(t *testing.T) {
	_, cw, _ := start(t)
	// The Commonwealth may not send an eligibility count; only States may.
	env, err := cw.Identity.Message(stID, "eligibility-count/1", count)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cw.Sender.Send(context.Background(), env)
	wantRejected(t, err, protocol.ReasonTypeNotAllowed)
}

func TestHandlerMissingIsRefusedAsNotAllowed(t *testing.T) {
	_, cw, st := start(t)
	delete(cw.Receiver.Handlers, "eligibility-count/1")
	env, _ := st.Identity.Message(cwID, "eligibility-count/1", count)
	_, err := st.Sender.Send(context.Background(), env)
	wantRejected(t, err, protocol.ReasonTypeNotAllowed)
}

func TestNotAddressedToRecipient(t *testing.T) {
	net, cw, st := start(t)
	// A record addressed to another State, delivered to the Commonwealth.
	env, _ := st.Identity.Message(s2ID, "eligibility-count/1", count)
	resp := post(t, cw, net.Nodes[stID].Sender.HTTP, env)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status %d, want 422", resp.StatusCode)
	}
}

func TestForgedSenderIsUntrusted(t *testing.T) {
	_, _, st := start(t)
	_, impostor, _ := ed25519.GenerateKey(rand.Reader)
	forged := st.Identity
	forged.Key = impostor
	env, _ := forged.Message(cwID, "eligibility-count/1", count)
	_, err := st.Sender.Send(context.Background(), env)
	wantRejected(t, err, protocol.ReasonUntrusted)
}

func TestFutureDated(t *testing.T) {
	_, cw, st := start(t)
	cw.Receiver.Now = func() time.Time { return time.Now().Add(-time.Hour) }
	env, _ := st.Identity.Message(cwID, "eligibility-count/1", count)
	_, err := st.Sender.Send(context.Background(), env)
	wantRejected(t, err, protocol.ReasonFutureDated)
}

func TestHandlerRefusal(t *testing.T) {
	_, cw, st := start(t)
	cw.Receiver.Handlers["eligibility-count/1"] = func(context.Context, *record.Envelope) error {
		return errors.New("period already reported")
	}
	env, _ := st.Identity.Message(cwID, "eligibility-count/1", count)
	_, err := st.Sender.Send(context.Background(), env)
	wantRejected(t, err, protocol.ReasonRefused)

	// A refused record is not stored, so it can be sent again once fixed.
	cw.Receiver.Handlers["eligibility-count/1"] = func(context.Context, *record.Envelope) error { return nil }
	if rc, err := st.Sender.Send(context.Background(), env); err != nil || rc.Status != protocol.StatusAccepted {
		t.Errorf("resend after refusal: %+v, %v", rc, err)
	}
}

func TestMalformedBody(t *testing.T) {
	net, cw, _ := start(t)
	resp, err := net.Nodes[stID].Sender.HTTP.Post(cw.Server.URL+"/inbox", "application/json", bytes.NewBufferString("{not json"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
	resp, err = net.Nodes[stID].Sender.HTTP.Get(cw.Server.URL + "/inbox")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status %d, want 405", resp.StatusCode)
	}
}

// redirect sends every request to another host, as a network attacker
// could.
type redirect struct {
	to   string
	next http.RoundTripper
}

func (r redirect) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Host = r.to
	return r.next.RoundTrip(req)
}

func TestReceiptFromWrongInstanceIsNotAccepted(t *testing.T) {
	net, _, st := start(t)
	// Traffic meant for the Commonwealth reaches the other State instead,
	// whose receipt is signed by the wrong instance.
	other := net.Nodes[s2ID].Server.Listener.Addr().String()
	sender := *st.Sender
	sender.HTTP = &http.Client{Transport: redirect{to: other, next: st.Sender.HTTP.Transport}}
	env, _ := st.Identity.Message(cwID, "eligibility-count/1", count)
	if _, err := sender.Send(context.Background(), env); !errors.Is(err, protocol.ErrNoReceipt) {
		t.Errorf("got %v, want ErrNoReceipt", err)
	}
}

func post(t *testing.T, to *network.Node, client *http.Client, env *record.Envelope) *http.Response {
	t.Helper()
	data, _ := env.Marshal()
	resp, err := client.Post(to.Server.URL+"/inbox", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}
