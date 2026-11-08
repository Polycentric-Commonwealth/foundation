package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/polycentric-commonwealth/foundation/dividend"
	"github.com/polycentric-commonwealth/foundation/ledger"
	"github.com/polycentric-commonwealth/foundation/protocol"
	"github.com/polycentric-commonwealth/foundation/record"
)

func protocolIdentity() protocol.Identity {
	return protocol.Identity{Instance: state.id, Layer: record.State, KeyID: "k1", Key: state.priv}
}

type party struct {
	id    string
	layer record.Layer
	priv  ed25519.PrivateKey
}

func newParty(id string, layer record.Layer) party {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return party{id, layer, priv}
}

func (p party) sign(t *testing.T, to, typ string, payload any) *record.Envelope {
	t.Helper()
	env, err := record.New(p.id, "k1", p.layer, typ, payload)
	if err != nil {
		t.Fatal(err)
	}
	env.To = to
	if err := env.Sign(p.priv); err != nil {
		t.Fatal(err)
	}
	return env
}

var (
	state = newParty("state.example", record.State)
	cw    = newParty("commonwealth.example", record.Commonwealth)
)

func refs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("R-%06d", i+1)
	}
	return out
}

func person(ref string) (Person, error) {
	return Person{Name: "Person " + ref, BirthDate: "1980-01-01"}, nil
}

// counted builds a recipient list for the given people and the count record
// that commits to it.
func counted(t *testing.T, people []string) ([]Entry, *record.Envelope) {
	t.Helper()
	entries, root, err := BuildList(people)
	if err != nil {
		t.Fatal(err)
	}
	n := int64(len(entries))
	count := state.sign(t, cw.id, dividend.EligibilityCountType, dividend.EligibilityCount{
		Period: "2027-01", Residents: n, Adults: n, DividendRecipients: n, RecipientsRoot: ledger.EncodeHash(root)})
	return entries, count
}

func audit(t *testing.T, count *record.Envelope, entries []Entry) (*record.Envelope, *record.Envelope) {
	t.Helper()
	req, err := NewRequest(count)
	if err != nil {
		t.Fatal(err)
	}
	reqEnv := cw.sign(t, state.id, RequestType, req)
	resp, err := Open(count, reqEnv, entries, person)
	if err != nil {
		t.Fatal(err)
	}
	return reqEnv, state.sign(t, cw.id, ResponseType, resp)
}

func failures(results []Result) int {
	n := 0
	for _, r := range results {
		if !r.Valid {
			n++
		}
	}
	return n
}

func TestBuildList(t *testing.T) {
	entries, root, err := BuildList(refs(50))
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(entries); i++ {
		if string(entries[i-1].Commitment[:]) >= string(entries[i].Commitment[:]) {
			t.Fatal("commitments are not strictly increasing")
		}
	}
	if ledger.RootHash(LeafHashes(entries)) != root {
		t.Error("root does not match the entries")
	}
	// Fresh salts: the same people give a different, unlinkable list.
	_, root2, _ := BuildList(refs(50))
	if root == root2 {
		t.Error("two lists of the same people have the same root")
	}
	if _, _, err := BuildList([]string{"R-1", "R-1"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("duplicate reference: %v", err)
	}
}

func TestSample(t *testing.T) {
	seed := []byte("0123456789abcdef0123456789abcdef")
	a := Sample(seed, "count-a", 1000, 500)
	if len(a) != 500 {
		t.Fatalf("sample has %d positions", len(a))
	}
	seen := map[uint64]bool{}
	for _, p := range a {
		if p >= 1000 || seen[p] {
			t.Fatalf("position %d is out of range or repeated", p)
		}
		seen[p] = true
	}
	b := Sample(seed, "count-a", 1000, 500)
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("the same inputs gave a different sample")
		}
	}
	if c := Sample(seed, "count-b", 1000, 500); c[0] == a[0] && c[1] == a[1] && c[2] == a[2] {
		t.Error("a different count gave the same sample")
	}
	if len(Sample(seed, "x", 7, 500)) != 7 {
		t.Error("a sample larger than the list should take the whole list")
	}
	// Positions should be spread evenly: each decile of a large list gets
	// roughly a tenth of a large sample.
	var deciles [10]int
	for _, p := range Sample(seed, "spread", 1_000_000, 600) {
		deciles[p/100_000]++
	}
	for d, n := range deciles {
		if n < 30 || n > 95 {
			t.Errorf("decile %d has %d of 600 positions", d, n)
		}
	}
}

func TestHonestStatePasses(t *testing.T) {
	entries, count := counted(t, refs(1200))
	req, resp := audit(t, count, entries)
	results, err := Check(count, req, resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != DefaultSample || failures(results) != 0 {
		t.Fatalf("%d results, %d failures", len(results), failures(results))
	}
	// The response carries personal data only for the sample.
	var r Response
	json.Unmarshal(resp.Payload, &r)
	if len(r.Openings) != DefaultSample {
		t.Errorf("response opened %d people", len(r.Openings))
	}
	if size := len(resp.Payload); size > 1<<20 {
		t.Errorf("response payload is %d bytes, over the inbox limit", size)
	}
}

func TestSmallListIsCheckedInFull(t *testing.T) {
	entries, count := counted(t, refs(12))
	req, resp := audit(t, count, entries)
	results, err := Check(count, req, resp)
	if err != nil || len(results) != 12 || failures(results) != 0 {
		t.Fatalf("%d results, %d failures, %v", len(results), failures(results), err)
	}
}

func TestTamperedOpeningsFail(t *testing.T) {
	entries, count := counted(t, refs(300))
	reqEnv, respEnv := audit(t, count, entries)
	var resp Response
	json.Unmarshal(respEnv.Payload, &resp)

	tamper := map[string]func(r *Response){
		"swapped reference": func(r *Response) { r.Openings[0].Ref = "R-999999" },
		"wrong salt":        func(r *Response) { r.Openings[1].Salt = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) },
		"bad proof":         func(r *Response) { r.Openings[2].Inclusion = r.Openings[3].Inclusion },
		"wrong position":    func(r *Response) { r.Openings[3].Index = r.Openings[4].Index },
		"missing name":      func(r *Response) { r.Openings[4].Name = "" },
		"opening withheld":  func(r *Response) { r.Openings = r.Openings[:len(r.Openings)-1] },
	}
	for name, change := range tamper {
		t.Run(name, func(t *testing.T) {
			var r Response
			b, _ := json.Marshal(resp)
			json.Unmarshal(b, &r)
			change(&r)
			results, err := Check(count, reqEnv, state.sign(t, cw.id, ResponseType, r))
			if err != nil {
				t.Fatal(err)
			}
			if failures(results) != 1 {
				t.Errorf("%d failures, want 1", failures(results))
			}
		})
	}
}

func TestResponseMustAnswerTheRequest(t *testing.T) {
	entries, count := counted(t, refs(20))
	reqEnv, respEnv := audit(t, count, entries)
	_, otherCount := counted(t, refs(20))
	if _, err := Check(otherCount, reqEnv, respEnv); !errors.Is(err, ErrInvalid) {
		t.Errorf("response checked against another count: %v", err)
	}
	otherReq, _ := NewRequest(count)
	if _, err := Check(count, cw.sign(t, state.id, RequestType, otherReq), respEnv); !errors.Is(err, ErrInvalid) {
		t.Errorf("response checked against another request: %v", err)
	}
	var r Response
	json.Unmarshal(respEnv.Payload, &r)
	impostor := newParty("other.example", record.State)
	if _, err := Check(count, reqEnv, impostor.sign(t, cw.id, ResponseType, r)); !errors.Is(err, ErrInvalid) {
		t.Errorf("response from another State: %v", err)
	}
	// The State cannot open a list other than the one it committed to.
	entries2, _, _ := BuildList(refs(20))
	if _, err := Open(count, reqEnv, entries2, person); !errors.Is(err, ErrInvalid) {
		t.Errorf("opening a different list: %v", err)
	}
}

// TestGhostsAreCaught simulates a State that adds invented people to its
// list. The Audit Office checks each opening in the field, where ghosts
// cannot be found.
func TestGhostsAreCaught(t *testing.T) {
	real := refs(9900)
	people := append(append([]string(nil), real...), func() []string {
		g := make([]string, 100) // 1% ghosts
		for i := range g {
			g[i] = fmt.Sprintf("G-%06d", i)
		}
		return g
	}()...)
	isReal := map[string]bool{}
	for _, r := range real {
		isReal[r] = true
	}

	caught, trials := 0, 20
	var totalExcess int64
	for i := 0; i < trials; i++ {
		entries, count := counted(t, people)
		reqEnv, respEnv := audit(t, count, entries)
		results, err := Check(count, reqEnv, respEnv)
		if err != nil {
			t.Fatal(err)
		}
		unverified := failures(results)
		for _, r := range results {
			if r.Valid && !isReal[r.Opening.Ref] { // field verification
				unverified++
			}
		}
		if unverified > 0 {
			caught++
		}
		s, _ := dividend.NewSettlement(count, "25.50")
		f, err := NewFinding(count, reqEnv, s, len(results), unverified, DefaultMultiplier)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Validate(); err != nil {
			t.Fatal(err)
		}
		totalExcess += f.EstimatedExcess
	}
	// Escaping one audit has probability about 0.99^500 ≈ 0.7%.
	if caught < trials-1 {
		t.Errorf("ghosts were caught in only %d of %d audits", caught, trials)
	}
	// On average the estimate is close to the 100 ghosts actually added.
	if avg := float64(totalExcess) / float64(trials); math.Abs(avg-100) > 40 {
		t.Errorf("average estimated excess %.0f, want about 100", avg)
	}
}

func TestFindingArithmetic(t *testing.T) {
	_, count := counted(t, refs(1000))
	req, _ := NewRequest(count)
	reqEnv := cw.sign(t, state.id, RequestType, req)
	s, _ := dividend.NewSettlement(count, "25.50")

	tests := []struct {
		unverified int
		excess     int64
		repayment  string
	}{
		{0, 0, "0"},
		{5, 10, "765"}, // 5/500 × 1000 = 10; 10 × 25.50 × 3
		{1, 2, "153"},  // 1/500 × 1000 = 2
		{500, 1000, "76500"},
	}
	for _, tt := range tests {
		f, err := NewFinding(count, reqEnv, s, 500, tt.unverified, DefaultMultiplier)
		if err != nil {
			t.Fatal(err)
		}
		if f.EstimatedExcess != tt.excess || f.Repayment != tt.repayment {
			t.Errorf("%d unverified: excess %d, repayment %s; want %d, %s", tt.unverified, f.EstimatedExcess, f.Repayment, tt.excess, tt.repayment)
		}
	}
	// Rounding: 1 of 3 sampled in a list of 10 is 3.33, which rounds to 3;
	// 1 of 4 in a list of 10 is 2.5, which rounds up to 3.
	_, small := counted(t, refs(10))
	smallReq := cw.sign(t, state.id, RequestType, Request{Count: small.ID, Seed: req.Seed, SampleSize: 4})
	ss, _ := dividend.NewSettlement(small, "1")
	for _, c := range []struct{ sampled, want int }{{3, 3}, {4, 3}} {
		f, _ := NewFinding(small, smallReq, ss, c.sampled, 1, "1")
		if f.EstimatedExcess != int64(c.want) {
			t.Errorf("1 of %d: excess %d, want %d", c.sampled, f.EstimatedExcess, c.want)
		}
	}

	bad, _ := NewFinding(count, reqEnv, s, 500, 5, DefaultMultiplier)
	bad.Repayment = "1"
	if err := bad.Validate(); !errors.Is(err, ErrInvalid) {
		t.Errorf("inconsistent repayment: %v", err)
	}
}

func TestAuditResponseIsNeverLogged(t *testing.T) {
	entries, count := counted(t, refs(5))
	_, resp := audit(t, count, entries)
	log := ledger.NewLog(protocolIdentity(), nil)
	if _, err := log.Append(resp); !errors.Is(err, ledger.ErrInvalid) {
		t.Errorf("logging an audit response: %v", err)
	}
}

// BenchmarkMillion measures a State of one million residents: building the
// committed list, and answering an audit of 500 entries.
func BenchmarkMillion(b *testing.B) {
	people := make([]string, 1_000_000)
	for i := range people {
		people[i] = fmt.Sprintf("R-%07d", i)
	}
	for i := 0; i < b.N; i++ {
		entries, root, err := BuildList(people)
		if err != nil {
			b.Fatal(err)
		}
		n := int64(len(entries))
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		count, _ := record.New("state.example", "k1", record.State, dividend.EligibilityCountType,
			dividend.EligibilityCount{Period: "2027-01", Residents: n, Adults: n, DividendRecipients: n, RecipientsRoot: ledger.EncodeHash(root)})
		count.Sign(priv)
		req, _ := NewRequest(count)
		reqEnv, _ := record.New("commonwealth.example", "k1", record.Commonwealth, RequestType, req)
		reqEnv.Sign(priv)
		if _, err := Open(count, reqEnv, entries, person); err != nil {
			b.Fatal(err)
		}
	}
}
