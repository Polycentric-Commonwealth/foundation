package ledger_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/polycentric-commonwealth/foundation/internal/network"
	"github.com/polycentric-commonwealth/foundation/ledger"
	"github.com/polycentric-commonwealth/foundation/protocol"
	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"
)

const (
	cwID = "commonwealth.example"
	stID = "state.example"
	w1ID = "west.example"
	w2ID = "east.example"
)

var witnesses = []string{cwID, w1ID, w2ID}

var policy = ledger.WitnessPolicy{Witnesses: witnesses, Threshold: 2}

func start(t *testing.T) *network.Network {
	t.Helper()
	net, err := network.Start(
		network.Spec{Instance: cwID, Layer: record.Commonwealth, Name: "Commonwealth"},
		network.Spec{Instance: stID, Layer: record.State, Name: "State", Parent: cwID},
		network.Spec{Instance: w1ID, Layer: record.State, Name: "West", Parent: cwID},
		network.Spec{Instance: w2ID, Layer: record.State, Name: "East", Parent: cwID},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(net.Close)
	return net
}

// logRecord signs a record from node, optionally backdated, and logs it.
func logRecord(t *testing.T, node *network.Node, n int, issuedAt *time.Time) (*record.Envelope, uint64) {
	t.Helper()
	env, err := node.Identity.Message(cwID, "eligibility-count/1",
		map[string]any{"period": "2027-01", "residents": n, "adults": n, "dividend_recipients": n})
	if err != nil {
		t.Fatal(err)
	}
	if issuedAt != nil {
		env.IssuedAt = issuedAt.UTC().Format(time.RFC3339)
		if err := env.Sign(node.Identity.Key); err != nil {
			t.Fatal(err)
		}
	}
	idx, err := node.Log.Append(env)
	if err != nil {
		t.Fatal(err)
	}
	return env, idx
}

// publish checkpoints node's log and collects cosignatures from witnesses.
func publish(t *testing.T, net *network.Network, node *network.Node) int {
	t.Helper()
	if _, err := node.Log.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	n, err := node.Log.RequestCosignatures(context.Background(), node.Registry, net.HTTP, witnesses)
	if err != nil {
		t.Fatalf("cosignatures: %v", err)
	}
	return n
}

// evidenceAtLatest returns evidence for entry idx from the log's latest
// checkpoint, rather than the earliest one Log.Evidence prefers.
func evidenceAtLatest(t *testing.T, node *network.Node, idx uint64) *ledger.Evidence {
	t.Helper()
	ev, err := node.Log.Evidence(idx)
	if err != nil {
		t.Fatal(err)
	}
	cp, cosigs, _ := node.Log.Latest()
	var payload ledger.Checkpoint
	if err := json.Unmarshal(cp.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	proof, err := node.Log.InclusionProof(idx, payload.Size)
	if err != nil {
		t.Fatal(err)
	}
	ev.Checkpoint, ev.Cosignatures, ev.Inclusion = cp, cosigs, nil
	for _, h := range proof {
		ev.Inclusion = append(ev.Inclusion, ledger.EncodeHash(h))
	}
	return ev
}

func TestEvidenceEndToEnd(t *testing.T) {
	net := start(t)
	st := net.Nodes[stID]
	var envs []*record.Envelope
	for i := 1; i <= 5; i++ {
		env, _ := logRecord(t, st, i, nil)
		envs = append(envs, env)
	}
	if n := publish(t, net, st); n != 3 {
		t.Fatalf("collected %d cosignatures, want 3", n)
	}
	before := time.Now().Add(-time.Minute)

	verifier := net.Nodes[w1ID].Registry
	for i, env := range envs {
		ev, err := st.Log.Evidence(uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		witnessed, err := ledger.VerifyEvidence(verifier, ev, policy)
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		if witnessed.Before(before) || witnessed.After(time.Now().Add(time.Second)) {
			t.Errorf("witnessed time %s is not now", witnessed)
		}
		if err := ledger.VerifyRecord(verifier, env, ev, policy); err != nil {
			t.Errorf("VerifyRecord: %v", err)
		}
	}
}

func TestLogGrowsAcrossCheckpoints(t *testing.T) {
	net := start(t)
	st := net.Nodes[stID]
	logRecord(t, st, 1, nil)
	publish(t, net, st)
	for i := 2; i <= 7; i++ {
		logRecord(t, st, i, nil)
		if n := publish(t, net, st); n != 3 {
			t.Fatalf("checkpoint at size %d: %d cosignatures", i, n)
		}
	}
	// A new Log over the same storage has forgotten what witnesses saw;
	// each witness answers 409 with its size and the log retries.
	fresh := ledger.NewLog(st.Identity, st.Log.Storage)
	logRecord(t, &network.Node{Identity: st.Identity, Log: fresh}, 8, nil)
	if _, err := fresh.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if n, err := fresh.RequestCosignatures(context.Background(), st.Registry, net.HTTP, witnesses); err != nil || n != 3 {
		t.Fatalf("after 409 retry: %d cosignatures, %v", n, err)
	}
}

func TestWitnessDetectsFork(t *testing.T) {
	net := start(t)
	st := net.Nodes[stID]
	logRecord(t, st, 1, nil)
	logRecord(t, st, 2, nil)
	publish(t, net, st)

	// The same instance keeps a second, different history.
	forked := ledger.NewLog(st.Identity, nil)
	fake := &network.Node{Identity: st.Identity, Log: forked}
	logRecord(t, fake, 1, nil)
	logRecord(t, fake, 99, nil)
	logRecord(t, fake, 3, nil)
	if _, err := forked.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	n, err := forked.RequestCosignatures(context.Background(), st.Registry, net.HTTP, witnesses)
	if n != 0 || err == nil || !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("forked log got %d cosignatures, err %v", n, err)
	}

	// A log that shrinks is refused too.
	short := ledger.NewLog(st.Identity, nil)
	logRecord(t, &network.Node{Identity: st.Identity, Log: short}, 1, nil)
	short.Checkpoint()
	if n, err := short.RequestCosignatures(context.Background(), st.Registry, net.HTTP, witnesses); n != 0 || err == nil {
		t.Fatalf("shrunk log got %d cosignatures, err %v", n, err)
	}
}

func TestEvidenceRejections(t *testing.T) {
	net := start(t)
	st := net.Nodes[stID]
	logRecord(t, st, 1, nil)
	other, _ := logRecord(t, st, 2, nil)
	publish(t, net, st)
	verifier := net.Nodes[w1ID].Registry

	fresh := func() *ledger.Evidence {
		ev, err := st.Log.Evidence(0)
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	tests := map[string]struct {
		change func(ev *ledger.Evidence) *ledger.Evidence
		policy ledger.WitnessPolicy
		want   error
	}{
		"wrong index":    {func(ev *ledger.Evidence) *ledger.Evidence { ev.Index = 1; return ev }, policy, ledger.ErrProof},
		"swapped record": {func(ev *ledger.Evidence) *ledger.Evidence { ev.Record = other; return ev }, policy, ledger.ErrProof},
		"tampered proof": {func(ev *ledger.Evidence) *ledger.Evidence {
			ev.Inclusion[0] = ledger.EncodeHash(ledger.LeafHash([]byte("x")))
			return ev
		}, policy, ledger.ErrProof},
		"threshold not met": {func(ev *ledger.Evidence) *ledger.Evidence { return ev },
			ledger.WitnessPolicy{Witnesses: witnesses, Threshold: 4}, ledger.ErrWitnesses},
		"witnesses outside policy": {func(ev *ledger.Evidence) *ledger.Evidence { return ev },
			ledger.WitnessPolicy{Witnesses: []string{"elsewhere.example"}, Threshold: 1}, ledger.ErrWitnesses},
		"one witness counted twice": {func(ev *ledger.Evidence) *ledger.Evidence {
			ev.Cosignatures = []*record.Envelope{ev.Cosignatures[0], ev.Cosignatures[0]}
			return ev
		}, policy, ledger.ErrWitnesses},
		"checkpoint from another instance": {func(ev *ledger.Evidence) *ledger.Evidence {
			w := net.Nodes[w1ID]
			logRecord(t, w, 1, nil)
			cp, _ := w.Log.Checkpoint()
			ev.Checkpoint = cp
			return ev
		}, policy, ledger.ErrInvalid},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ledger.VerifyEvidence(verifier, tt.change(fresh()), tt.policy)
			if !errors.Is(err, tt.want) {
				t.Errorf("got %v, want %v", err, tt.want)
			}
		})
	}
	if _, err := ledger.VerifyEvidence(verifier, fresh(), policy); err != nil {
		t.Errorf("unchanged evidence: %v", err)
	}
}

// TestStolenKey is the scenario the ledger exists for. A State's key is
// stolen; the thief signs a record backdated to before the theft. Once the
// State revokes the key from the time of the theft, the thief's record is
// refused, while the State's genuine earlier records still verify.
func TestStolenKey(t *testing.T) {
	net := start(t)
	st := net.Nodes[stID]
	verifier := net.Nodes[w1ID].Registry

	// The thief signs a record dated an hour ago, and even gets it logged
	// and witnessed now.
	theft := time.Now().Add(-30 * time.Minute)
	backdated := time.Now().Add(-time.Hour)
	forged, fidx := logRecord(t, st, 9999999, &backdated)
	publish(t, net, st)
	forgedEvidence, err := st.Log.Evidence(fidx)
	if err != nil {
		t.Fatal(err)
	}

	// Before revocation, the forged record looks valid.
	if err := ledger.VerifyRecord(verifier, forged, nil, policy); err != nil {
		t.Fatalf("before revocation: %v", err)
	}

	// The State revokes the stolen key from the time of the theft.
	if err := net.RevokeAndReplace(stID, theft); err != nil {
		t.Fatal(err)
	}

	if err := ledger.VerifyRecord(verifier, forged, nil, policy); !errors.Is(err, ledger.ErrNeedsEvidence) {
		t.Errorf("forged record without evidence: got %v, want ErrNeedsEvidence", err)
	}
	// Evidence from a checkpoint signed with the stolen key after the
	// theft is itself invalid.
	if err := ledger.VerifyRecord(verifier, forged, forgedEvidence, policy); !errors.Is(err, registry.ErrKeyNotValid) {
		t.Errorf("forged record with stolen-key checkpoint: got %v, want ErrKeyNotValid", err)
	}
	// Even once the State's own log, under its new key, includes the
	// forgery, it was witnessed only after the theft.
	publish(t, net, st)
	laterEvidence := evidenceAtLatest(t, st, fidx)
	if err := ledger.VerifyRecord(verifier, forged, laterEvidence, policy); !errors.Is(err, ledger.ErrTooLate) {
		t.Errorf("forged record with later evidence: got %v, want ErrTooLate", err)
	}
}

// TestRevocationKeepsWitnessedRecords: records witnessed before the
// revocation time stay valid; ones witnessed after do not.
func TestRevocationKeepsWitnessedRecords(t *testing.T) {
	net := start(t)
	st := net.Nodes[stID]
	verifier := net.Nodes[w1ID].Registry

	genuine, idx := logRecord(t, st, 1000, nil)
	publish(t, net, st)
	ev, err := st.Log.Evidence(idx)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(1100 * time.Millisecond)
	revokeAt := time.Now()
	time.Sleep(1100 * time.Millisecond)

	// Signed (backdated to before revokeAt) but only witnessed afterwards.
	backdated := revokeAt.Add(-2 * time.Second)
	late, lidx := logRecord(t, st, 2000, &backdated)
	publish(t, net, st)
	lateEv, err := st.Log.Evidence(lidx)
	if err != nil {
		t.Fatal(err)
	}

	stolen := st.Identity
	if err := net.RevokeAndReplace(stID, revokeAt); err != nil {
		t.Fatal(err)
	}
	if err := ledger.VerifyRecord(verifier, genuine, ev, policy); err != nil {
		t.Errorf("record witnessed before revocation: %v", err)
	}
	if err := ledger.VerifyRecord(verifier, late, lateEv, policy); !errors.Is(err, registry.ErrKeyNotValid) {
		t.Errorf("record in a checkpoint signed after revocation: got %v, want ErrKeyNotValid", err)
	}
	if err := ledger.VerifyRecord(verifier, genuine, lateEv, policy); !errors.Is(err, ledger.ErrInvalid) {
		t.Errorf("evidence for a different record: got %v, want ErrInvalid", err)
	}

	// Witnesses refuse checkpoints signed with the revoked key...
	thief := ledger.NewLog(stolen, st.Log.Storage)
	if _, err := thief.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if n, err := thief.RequestCosignatures(context.Background(), st.Registry, net.HTTP, witnesses); n != 0 || err == nil {
		t.Errorf("checkpoint signed with revoked key: %d cosignatures, err %v", n, err)
	}
	// ...but accept them from the replacement key.
	logRecord(t, st, 3000, nil)
	if n := publish(t, net, st); n != 3 {
		t.Errorf("checkpoint with new key: %d cosignatures", n)
	}
	// In a valid checkpoint under the new key, the backdated record was
	// still witnessed too late.
	if err := ledger.VerifyRecord(verifier, late, evidenceAtLatest(t, st, lidx), policy); !errors.Is(err, ledger.ErrTooLate) {
		t.Errorf("backdated record in new checkpoint: got %v, want ErrTooLate", err)
	}
	// The log offers the genuine record's earliest checkpoint, which still
	// proves it existed before the revocation.
	ev2, err := st.Log.Evidence(idx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.VerifyRecord(verifier, genuine, ev2, policy); err != nil {
		t.Errorf("genuine record from the log's chosen evidence: %v", err)
	}
}

func TestInboxRejectsRevokedKey(t *testing.T) {
	net := start(t)
	st, cw := net.Nodes[stID], net.Nodes[cwID]
	cw.Receiver.Handlers["eligibility-count/1"] = func(context.Context, *record.Envelope) error { return nil }
	stolen := st.Identity

	if err := net.RevokeAndReplace(stID, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	// Backdated so the key was valid at issued_at; still refused at the inbox.
	env, err := stolen.Message(cwID, "eligibility-count/1", map[string]any{"period": "2027-01", "residents": 1, "adults": 1, "dividend_recipients": 1})
	if err != nil {
		t.Fatal(err)
	}
	env.IssuedAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	env.Sign(stolen.Key)
	_, err = st.Sender.Send(context.Background(), env)
	if rc, ok := protocol.IsRejected(err); !ok || rc.Reason != protocol.ReasonUntrusted {
		t.Errorf("revoked key at inbox: %v", err)
	}

	// The same message signed with the new key is accepted.
	fresh, _ := st.Identity.Message(cwID, "eligibility-count/1", map[string]any{"period": "2027-01", "residents": 1, "adults": 1, "dividend_recipients": 1})
	if rc, err := st.Sender.Send(context.Background(), fresh); err != nil || rc.Status != protocol.StatusAccepted {
		t.Errorf("new key: %+v, %v", rc, err)
	}
}

func TestHTTPEndpoints(t *testing.T) {
	net := start(t)
	st := net.Nodes[stID]
	for i := 1; i <= 3; i++ {
		logRecord(t, st, i, nil)
	}
	publish(t, net, st)
	base := st.Server.URL + "/ledger/"

	get := func(path string, v any) int {
		t.Helper()
		resp, err := net.HTTP.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if v != nil && resp.StatusCode == http.StatusOK {
			if err := json.Unmarshal(data, v); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
		}
		return resp.StatusCode
	}

	var latest struct {
		Checkpoint   *record.Envelope   `json:"checkpoint"`
		Cosignatures []*record.Envelope `json:"cosignatures"`
	}
	if code := get("checkpoint", &latest); code != 200 || len(latest.Cosignatures) != 3 {
		t.Fatalf("checkpoint: %d, %d cosignatures", code, len(latest.Cosignatures))
	}
	cp, root, err := ledger.VerifyCheckpoint(net.Nodes[w2ID].Registry, latest.Checkpoint)
	if err != nil || cp.Size != 3 {
		t.Fatalf("served checkpoint: %+v, %v", cp, err)
	}

	var entries struct {
		Entries []*record.Envelope `json:"entries"`
	}
	if code := get("entries?start=0&end=3", &entries); code != 200 || len(entries.Entries) != 3 {
		t.Fatalf("entries: %d, %d", code, len(entries.Entries))
	}
	var proof struct {
		Hashes []string `json:"hashes"`
	}
	if code := get("proof/inclusion?index=1&size=3", &proof); code != 200 {
		t.Fatalf("inclusion: %d", code)
	}
	entry, _ := ledger.EntryBytes(entries.Entries[1])
	hashes := make([]ledger.Hash, len(proof.Hashes))
	for i, h := range proof.Hashes {
		hashes[i], _ = ledger.DecodeHash(h)
	}
	if err := ledger.VerifyInclusion(1, 3, ledger.LeafHash(entry), hashes, root); err != nil {
		t.Errorf("served inclusion proof: %v", err)
	}
	if code := get("proof/consistency?first=1&second=3", &proof); code != 200 {
		t.Fatalf("consistency: %d", code)
	}
	var ev ledger.Evidence
	if code := get("evidence?index=2", &ev); code != 200 {
		t.Fatalf("evidence: %d", code)
	}
	if _, err := ledger.VerifyEvidence(net.Nodes[w2ID].Registry, &ev, policy); err != nil {
		t.Errorf("served evidence: %v", err)
	}

	for _, bad := range []string{"entries?start=2&end=9", "proof/inclusion?index=5&size=3", "evidence?index=9", "nothing"} {
		if code := get(bad, nil); code == 200 {
			t.Errorf("%s: status 200", bad)
		}
	}
}

func TestLogRefusesOthersRecords(t *testing.T) {
	net := start(t)
	st, cw := net.Nodes[stID], net.Nodes[cwID]
	env, _ := cw.Identity.Message(stID, "dividend-settlement/1", map[string]string{"x": "y"})
	if _, err := st.Log.Append(env); !errors.Is(err, ledger.ErrInvalid) {
		t.Errorf("appending another instance's record: %v", err)
	}
	cp, _ := st.Log.Checkpoint()
	if _, err := st.Log.Append(cp); !errors.Is(err, ledger.ErrInvalid) {
		t.Errorf("appending a checkpoint: %v", err)
	}
}
