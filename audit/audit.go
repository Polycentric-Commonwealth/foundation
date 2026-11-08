// Package audit implements eligibility audits (specs/eligibility-audit.md):
// a State commits to the list of people it counted, and the Commonwealth's
// Audit Office checks a random sample of them.
//
// The State uses BuildList when it counts and Open when it is audited. The
// Audit Office uses NewRequest, Check and NewFinding.
package audit

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"

	"github.com/polycentric-commonwealth/foundation/amount"
	"github.com/polycentric-commonwealth/foundation/dividend"
	"github.com/polycentric-commonwealth/foundation/ledger"
	"github.com/polycentric-commonwealth/foundation/record"
)

// Record types, limits and recommended values.
const (
	RequestType  = "audit-request/1"
	ResponseType = "audit-response/1"
	FindingType  = "audit-finding/1"

	MaxSample         = 600
	DefaultSample     = 500
	DefaultMultiplier = "3"
)

// ErrInvalid reports a list, request, response or finding that does not
// follow the specification.
var ErrInvalid = errors.New("audit: invalid")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Commit returns the commitment to one person: SHA-256(salt || ref).
func Commit(salt [32]byte, ref string) ledger.Hash {
	h := sha256.New()
	h.Write(salt[:])
	h.Write([]byte(ref))
	var out ledger.Hash
	h.Sum(out[:0])
	return out
}

// Entry is one person in a State's committed recipient list. The State keeps
// entries privately until the count's audit is closed.
type Entry struct {
	Index      uint64
	Ref        string
	Salt       [32]byte
	Commitment ledger.Hash
}

// BuildList commits to the given people with fresh salts, sorts the
// commitments and returns the entries in list order with the list's root.
func BuildList(refs []string) ([]Entry, ledger.Hash, error) {
	seen := make(map[string]bool, len(refs))
	entries := make([]Entry, len(refs))
	for i, ref := range refs {
		if ref == "" || len(ref) > 128 {
			return nil, ledger.Hash{}, invalid("references must be 1 to 128 bytes")
		}
		if seen[ref] {
			return nil, ledger.Hash{}, invalid("reference %q is listed twice", ref)
		}
		seen[ref] = true
		if _, err := rand.Read(entries[i].Salt[:]); err != nil {
			return nil, ledger.Hash{}, err
		}
		entries[i].Ref = ref
		entries[i].Commitment = Commit(entries[i].Salt, ref)
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].Commitment[:], entries[j].Commitment[:]) < 0
	})
	for i := range entries {
		entries[i].Index = uint64(i)
	}
	return entries, ledger.RootHash(LeafHashes(entries)), nil
}

// LeafHashes returns the Merkle leaf hashes of the entries, in list order.
func LeafHashes(entries []Entry) []ledger.Hash {
	out := make([]ledger.Hash, len(entries))
	for i, e := range entries {
		out[i] = ledger.LeafHash(e.Commitment[:])
	}
	return out
}

// Sample returns the positions to audit in a list of the given size, derived
// from the request's seed and the count's id, in the order chosen.
func Sample(seed []byte, countID string, size uint64, n int) []uint64 {
	if size == 0 || n <= 0 {
		return nil
	}
	if uint64(n) > size {
		n = int(size)
	}
	limit := (^uint64(0) / size) * size
	chosen := make(map[uint64]bool, n)
	out := make([]uint64, 0, n)
	var counter [8]byte
	for j := uint64(0); len(out) < n; j++ {
		binary.BigEndian.PutUint64(counter[:], j)
		h := sha256.New()
		h.Write([]byte("pc-audit-sample/1"))
		h.Write(seed)
		h.Write([]byte(countID))
		h.Write(counter[:])
		v := binary.BigEndian.Uint64(h.Sum(nil)[:8])
		if v >= limit {
			continue
		}
		if p := v % size; !chosen[p] {
			chosen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// Request is the payload of audit-request/1.
type Request struct {
	Count      string `json:"count"`
	Seed       string `json:"seed"`
	SampleSize int    `json:"sample_size"`
}

// NewRequest returns an audit request for an eligibility-count record, with
// a fresh random seed and the recommended sample size.
func NewRequest(count *record.Envelope) (*Request, error) {
	c, err := dividend.DecodeCount(count)
	if err != nil {
		return nil, err
	}
	if c.DividendRecipients == 0 {
		return nil, invalid("an empty list has nothing to audit")
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	n := DefaultSample
	if c.DividendRecipients < int64(n) {
		n = int(c.DividendRecipients)
	}
	return &Request{Count: count.ID, Seed: base64.RawURLEncoding.EncodeToString(seed), SampleSize: n}, nil
}

func (r *Request) validate() ([]byte, error) {
	if r.SampleSize < 1 || r.SampleSize > MaxSample {
		return nil, invalid("sample_size must be between 1 and %d", MaxSample)
	}
	seed, err := base64.RawURLEncoding.DecodeString(r.Seed)
	if err != nil || len(seed) != 32 {
		return nil, invalid("seed must be 32 bytes of unpadded base64url")
	}
	return seed, nil
}

// Opening reveals one sampled entry.
type Opening struct {
	Index      uint64   `json:"index"`
	Commitment string   `json:"commitment"`
	Salt       string   `json:"salt"`
	Ref        string   `json:"ref"`
	Name       string   `json:"name"`
	BirthDate  string   `json:"birth_date"`
	Inclusion  []string `json:"inclusion"`
}

// Response is the payload of audit-response/1. It contains personal data
// for the sampled people only, and must never be logged.
type Response struct {
	Request  string    `json:"request"`
	Count    string    `json:"count"`
	Openings []Opening `json:"openings"`
}

// Person is what the State discloses about one sampled person.
type Person struct {
	Name      string
	BirthDate string
}

// Open is the State's side of an audit: it derives the sample from the
// request and opens exactly those entries of the list behind the count.
func Open(count, request *record.Envelope, entries []Entry, person func(ref string) (Person, error)) (*Response, error) {
	var req Request
	if err := decode(request, RequestType, &req); err != nil {
		return nil, err
	}
	seed, err := req.validate()
	if err != nil {
		return nil, err
	}
	if req.Count != count.ID {
		return nil, invalid("request is for count %s, not %s", req.Count, count.ID)
	}
	c, err := dividend.DecodeCount(count)
	if err != nil {
		return nil, err
	}
	if int64(len(entries)) != c.DividendRecipients {
		return nil, invalid("list has %d entries but the count reported %d", len(entries), c.DividendRecipients)
	}
	tree := ledger.NewTree(LeafHashes(entries))
	if ledger.EncodeHash(tree.Root()) != c.RecipientsRoot {
		return nil, invalid("list does not match the count's recipients_root")
	}

	resp := &Response{Request: request.ID, Count: count.ID}
	for _, idx := range Sample(seed, count.ID, uint64(len(entries)), req.SampleSize) {
		e := entries[idx]
		p, err := person(e.Ref)
		if err != nil {
			return nil, fmt.Errorf("audit: opening %s: %w", e.Ref, err)
		}
		proof, err := tree.InclusionProof(idx)
		if err != nil {
			return nil, err
		}
		o := Opening{Index: idx, Commitment: ledger.EncodeHash(e.Commitment), Salt: base64.RawURLEncoding.EncodeToString(e.Salt[:]),
			Ref: e.Ref, Name: p.Name, BirthDate: p.BirthDate}
		for _, h := range proof {
			o.Inclusion = append(o.Inclusion, ledger.EncodeHash(h))
		}
		resp.Openings = append(resp.Openings, o)
	}
	return resp, nil
}

// Result is the Audit Office's structural check of one sampled position.
// Openings that pass still need verifying in the field.
type Result struct {
	Index   uint64
	Opening *Opening // nil if the State did not open this position
	Valid   bool
	Problem string
}

var datePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// Check verifies a response against the request and the count, and returns
// one result per sampled position. An error means the response as a whole
// does not answer this request.
func Check(count, request, response *record.Envelope) ([]Result, error) {
	var req Request
	if err := decode(request, RequestType, &req); err != nil {
		return nil, err
	}
	seed, err := req.validate()
	if err != nil {
		return nil, err
	}
	var resp Response
	if err := decode(response, ResponseType, &resp); err != nil {
		return nil, err
	}
	if req.Count != count.ID || resp.Count != count.ID || resp.Request != request.ID {
		return nil, invalid("response does not answer request %s for count %s", request.ID, count.ID)
	}
	if response.Issuer != count.Issuer {
		return nil, invalid("response is from %s, but the count is from %s", response.Issuer, count.Issuer)
	}
	c, err := dividend.DecodeCount(count)
	if err != nil {
		return nil, err
	}
	root, err := ledger.DecodeHash(c.RecipientsRoot)
	if err != nil {
		return nil, err
	}
	size := uint64(c.DividendRecipients)
	sample := Sample(seed, count.ID, size, req.SampleSize)
	if len(resp.Openings) > len(sample) {
		return nil, invalid("response opens %d entries; only %d were sampled", len(resp.Openings), len(sample))
	}

	results := make([]Result, len(sample))
	refs := map[string]bool{}
	for i, idx := range sample {
		results[i].Index = idx
		if i >= len(resp.Openings) {
			results[i].Problem = "not opened"
			continue
		}
		o := &resp.Openings[i]
		results[i].Opening = o
		results[i].Problem = checkOpening(o, idx, size, root)
		if results[i].Problem == "" && refs[o.Ref] {
			results[i].Problem = "the same person appears twice in the list"
		}
		refs[o.Ref] = true
		results[i].Valid = results[i].Problem == ""
	}
	return results, nil
}

func checkOpening(o *Opening, idx, size uint64, root ledger.Hash) string {
	if o.Index != idx {
		return fmt.Sprintf("opened position %d instead of %d", o.Index, idx)
	}
	if o.Ref == "" || len(o.Ref) > 128 || o.Name == "" || !datePattern.MatchString(o.BirthDate) {
		return "reference, name or date of birth missing or malformed"
	}
	saltBytes, err := base64.RawURLEncoding.DecodeString(o.Salt)
	if err != nil || len(saltBytes) != 32 {
		return "malformed salt"
	}
	var salt [32]byte
	copy(salt[:], saltBytes)
	commitment, err := ledger.DecodeHash(o.Commitment)
	if err != nil || Commit(salt, o.Ref) != commitment {
		return "commitment does not match the salt and reference"
	}
	proof := make([]ledger.Hash, len(o.Inclusion))
	for i, s := range o.Inclusion {
		if proof[i], err = ledger.DecodeHash(s); err != nil {
			return "malformed inclusion proof"
		}
	}
	if ledger.VerifyInclusion(idx, size, ledger.LeafHash(commitment[:]), proof, root) != nil {
		return "not in the committed list at this position"
	}
	return ""
}

// Finding is the payload of audit-finding/1.
type Finding struct {
	Count           string `json:"count"`
	Request         string `json:"request"`
	Sampled         int    `json:"sampled"`
	Unverified      int    `json:"unverified"`
	EstimatedExcess int64  `json:"estimated_excess"`
	Unit            string `json:"unit"`
	PerPerson       string `json:"per_person"`
	Multiplier      string `json:"multiplier"`
	Repayment       string `json:"repayment"`
}

// NewFinding computes the finding for an audited count: unverified is the
// number of sampled entries that failed the structural check or field
// verification. settlement is the settlement paid on the count.
func NewFinding(count, request *record.Envelope, settlement *dividend.Settlement, sampled, unverified int, multiplier string) (*Finding, error) {
	c, err := dividend.DecodeCount(count)
	if err != nil {
		return nil, err
	}
	if settlement.Basis != count.ID {
		return nil, invalid("settlement is not based on count %s", count.ID)
	}
	if sampled < 1 || sampled > MaxSample || unverified < 0 || unverified > sampled {
		return nil, invalid("need 1 to %d sampled and at most that many unverified", MaxSample)
	}
	// round(unverified × recipients ÷ sampled), halves up.
	excess := new(big.Int).Mul(big.NewInt(int64(unverified)), big.NewInt(c.DividendRecipients))
	excess.Mul(excess, big.NewInt(2))
	excess.Add(excess, big.NewInt(int64(sampled)))
	excess.Quo(excess, big.NewInt(2*int64(sampled)))

	f := &Finding{Count: count.ID, Request: request.ID, Sampled: sampled, Unverified: unverified,
		EstimatedExcess: excess.Int64(), Unit: settlement.Unit, PerPerson: settlement.PerPerson, Multiplier: multiplier}
	if f.Repayment, err = repayment(f); err != nil {
		return nil, err
	}
	return f, nil
}

func repayment(f *Finding) (string, error) {
	base, err := amount.MulInt(f.PerPerson, f.EstimatedExcess)
	if err != nil {
		return "", invalid("repayment: %v", err)
	}
	b, _ := amount.Parse(base)
	m, err := amount.Parse(f.Multiplier)
	if err != nil {
		return "", invalid("multiplier: %v", err)
	}
	out, err := amount.Format(new(big.Rat).Mul(b, m))
	if err != nil {
		return "", invalid("repayment: %v", err)
	}
	return out, nil
}

// Validate checks that the finding's numbers are consistent.
func (f *Finding) Validate() error {
	if f.Sampled < 1 || f.Unverified < 0 || f.Unverified > f.Sampled || f.EstimatedExcess < 0 {
		return invalid("inconsistent counts")
	}
	want, err := repayment(f)
	if err != nil {
		return err
	}
	if c, err := amount.Cmp(f.Repayment, want); err != nil || c != 0 {
		return invalid("repayment %s does not equal %d × %s × %s", f.Repayment, f.EstimatedExcess, f.PerPerson, f.Multiplier)
	}
	return nil
}

// DecodeFinding returns the validated payload of a finding record.
func DecodeFinding(env *record.Envelope) (*Finding, error) {
	var f Finding
	if err := decode(env, FindingType, &f); err != nil {
		return nil, err
	}
	return &f, f.Validate()
}

// DecodeRequest returns the validated payload of a request record.
func DecodeRequest(env *record.Envelope) (*Request, error) {
	var r Request
	if err := decode(env, RequestType, &r); err != nil {
		return nil, err
	}
	_, err := r.validate()
	return &r, err
}

func decode(env *record.Envelope, typ string, v any) error {
	if env.Type != typ {
		return invalid("record type is %q, not %q", env.Type, typ)
	}
	dec := json.NewDecoder(bytes.NewReader(env.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("payload: %v", err)
	}
	return nil
}
