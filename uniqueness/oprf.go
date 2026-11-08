// Package uniqueness implements the uniqueness registry of the federated
// identity specification (specs/federated-identity.md): a way to detect that
// the same person is counted by two States, or twice by one, without any
// central list of people.
//
// A State turns a resident's normalized identity attributes into a token
// with a threshold oblivious pseudorandom function (OPRF). The OPRF key is
// split among independent operators, so no operator alone can compute a
// token, and operators never see the attributes they help evaluate. The
// State then registers its residents' tokens with the Commonwealth's
// registry, which flags any token registered twice.
//
// The OPRF is the verifiable mode (VOPRF) of RFC 9497 with the suite
// ristretto255-SHA512. The key is shared with Shamir secret sharing and
// Feldman commitments; each operator proves its partial evaluation with the
// RFC 9497 DLEQ proof against its public share, and any threshold of valid
// partial evaluations combine, by Lagrange interpolation, into exactly the
// RFC 9497 output under the shared key.
package uniqueness

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/oprf"
	"github.com/cloudflare/circl/secretsharing"
	"github.com/cloudflare/circl/zk/dleq"
)

// SuiteID is the RFC 9497 ciphersuite used for tokens.
const SuiteID = "ristretto255-SHA512"

// MaxOperators is the largest number of operators a configuration may name.
const MaxOperators = 255

var (
	suite = oprf.SuiteRistretto255
	grp   = group.Ristretto255

	// proofParams are the RFC 9497 DLEQ parameters for the verifiable mode
	// (0x01) of the suite: the context string "OPRFV1-" || 0x01 || "-" ||
	// identifier.
	proofParams = dleq.Params{G: grp, H: crypto.SHA512, DST: []byte("OPRFV1-\x01-" + SuiteID)}
)

// Errors returned by the OPRF functions.
var (
	ErrInvalid      = errors.New("uniqueness: invalid")
	ErrNotEnough    = errors.New("uniqueness: not enough valid partial evaluations")
	ErrInvalidProof = errors.New("uniqueness: partial evaluation proof does not verify")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

var b64 = base64.RawURLEncoding

// Share is one operator's share of the OPRF key. It is secret.
type Share struct {
	Index int
	Key   group.Scalar
}

// String encodes the share as "<index>:<base64url key>", for storing it.
func (s Share) String() string {
	k, _ := s.Key.MarshalBinary()
	return strconv.Itoa(s.Index) + ":" + b64.EncodeToString(k)
}

// ParseShare decodes a share encoded by String.
func ParseShare(text string) (Share, error) {
	i, k, ok := strings.Cut(strings.TrimSpace(text), ":")
	if !ok {
		return Share{}, invalid("share must be <index>:<key>")
	}
	idx, err := strconv.Atoi(i)
	if err != nil || idx < 1 || idx > MaxOperators {
		return Share{}, invalid("share index must be 1 to %d", MaxOperators)
	}
	raw, err := b64.DecodeString(k)
	if err != nil {
		return Share{}, invalid("share key is not base64url")
	}
	key := grp.NewScalar()
	if err := key.UnmarshalBinary(raw); err != nil || key.IsZero() {
		return Share{}, invalid("share key is not a valid scalar")
	}
	return Share{Index: idx, Key: key}, nil
}

// Deal creates a fresh OPRF key and splits it into n shares, any threshold
// of which can evaluate the OPRF. It returns the Feldman commitments to the
// sharing polynomial, which are public, and the shares, one for each
// operator, which are secret. The dealer must erase the shares after handing
// them out; a distributed key generation that needs no dealer is planned.
func Deal(threshold, n int) (commitments []string, shares []Share, err error) {
	if threshold < 1 || n < threshold || n > MaxOperators {
		return nil, nil, invalid("need 1 <= threshold <= operators <= %d", MaxOperators)
	}
	secret := grp.RandomNonZeroScalar(rand.Reader)
	ss := secretsharing.New(rand.Reader, uint(threshold-1), secret)
	for _, c := range ss.CommitSecret() {
		enc, err := c.MarshalBinaryCompress()
		if err != nil {
			return nil, nil, err
		}
		commitments = append(commitments, b64.EncodeToString(enc))
	}
	for i, s := range ss.Share(uint(n)) {
		shares = append(shares, Share{Index: i + 1, Key: s.Value})
	}
	return commitments, shares, nil
}

// PublicKeys are the decoded Feldman commitments of a configuration. The
// first commitment is the group's OPRF public key; from all of them anyone
// can derive each operator's public share.
type PublicKeys struct {
	commitments []group.Element
}

// ParsePublicKeys decodes the commitments of a configuration. Their number is
// the threshold.
func ParsePublicKeys(commitments []string) (*PublicKeys, error) {
	if len(commitments) < 1 || len(commitments) > MaxOperators {
		return nil, invalid("need 1 to %d commitments", MaxOperators)
	}
	p := &PublicKeys{}
	for _, c := range commitments {
		e, err := decodeElement(c)
		if err != nil {
			return nil, invalid("commitment: %v", err)
		}
		p.commitments = append(p.commitments, e)
	}
	return p, nil
}

// Threshold is the number of operators whose partial evaluations are needed.
func (p *PublicKeys) Threshold() int { return len(p.commitments) }

// ShareKey returns the public share of the operator with the given index:
// the sum of commitment j times index^j.
func (p *PublicKeys) ShareKey(index int) group.Element {
	x := grp.NewScalar().SetUint64(uint64(index))
	last := len(p.commitments) - 1
	sum := grp.NewElement().Set(p.commitments[last])
	for j := last - 1; j >= 0; j-- {
		sum.Mul(sum, x)
		sum.Add(sum, p.commitments[j])
	}
	return sum
}

// Matches reports whether a secret share belongs to these commitments.
func (p *PublicKeys) Matches(s Share) bool {
	return grp.NewElement().MulGen(s.Key).IsEqual(p.ShareKey(s.Index))
}

func (p *PublicKeys) groupKey() (*oprf.PublicKey, error) {
	enc, err := p.commitments[0].MarshalBinaryCompress()
	if err != nil {
		return nil, err
	}
	pk := new(oprf.PublicKey)
	return pk, pk.UnmarshalBinary(suite, enc)
}

// Evaluate is an operator's partial evaluation of blinded elements, with a
// batched DLEQ proof that it used the key behind its public share.
func (s Share) Evaluate(blinded []string) (elements []string, proof string, err error) {
	if len(blinded) == 0 {
		return nil, "", invalid("no elements to evaluate")
	}
	req := &oprf.EvaluationRequest{}
	for _, b := range blinded {
		e, err := decodeElement(b)
		if err != nil {
			return nil, "", invalid("blinded element: %v", err)
		}
		req.Elements = append(req.Elements, e)
	}
	raw, err := s.Key.MarshalBinary()
	if err != nil {
		return nil, "", err
	}
	priv := new(oprf.PrivateKey)
	if err := priv.UnmarshalBinary(suite, raw); err != nil {
		return nil, "", err
	}
	ev, err := oprf.NewVerifiableServer(suite, priv).Evaluate(req)
	if err != nil {
		return nil, "", err
	}
	for _, e := range ev.Elements {
		enc, err := e.MarshalBinaryCompress()
		if err != nil {
			return nil, "", err
		}
		elements = append(elements, b64.EncodeToString(enc))
	}
	pr, err := ev.Proof.MarshalBinary()
	if err != nil {
		return nil, "", err
	}
	return elements, b64.EncodeToString(pr), nil
}

// Blinding holds a client's secret blinds for one batch of inputs, between
// Blind and Finalize.
type Blinding struct {
	keys *PublicKeys
	fin  *oprf.FinalizeData
	req  *oprf.EvaluationRequest
}

// Blind blinds a batch of OPRF inputs and returns the blinded elements to
// send to the operators.
func (p *PublicKeys) Blind(inputs [][]byte) (*Blinding, []string, error) {
	return p.blind(inputs, nil)
}

func (p *PublicKeys) blind(inputs [][]byte, blinds []oprf.Blind) (*Blinding, []string, error) {
	if len(inputs) == 0 {
		return nil, nil, invalid("no inputs")
	}
	gk, err := p.groupKey()
	if err != nil {
		return nil, nil, err
	}
	client := oprf.NewVerifiableClient(suite, gk)
	var fin *oprf.FinalizeData
	var req *oprf.EvaluationRequest
	if blinds == nil {
		fin, req, err = client.Blind(inputs)
	} else {
		fin, req, err = client.DeterministicBlind(inputs, blinds)
	}
	if err != nil {
		return nil, nil, err
	}
	out := make([]string, len(req.Elements))
	for i, e := range req.Elements {
		enc, err := e.MarshalBinaryCompress()
		if err != nil {
			return nil, nil, err
		}
		out[i] = b64.EncodeToString(enc)
	}
	return &Blinding{keys: p, fin: fin, req: req}, out, nil
}

// Partial is one operator's answer to a blinded batch.
type Partial struct {
	Index    int
	Elements []string
	Proof    string
}

// Finalize verifies the operators' partial evaluations, combines a threshold
// of valid ones and returns the OPRF outputs, one for each input. It also
// returns the indexes of operators whose answers were invalid, so they can
// be reported; their answers are ignored.
func (b *Blinding) Finalize(partials []Partial) (outputs [][]byte, faulty []int, err error) {
	n := len(b.req.Elements)
	type good struct {
		index    int
		elements []group.Element
	}
	var valid []good
	seen := map[int]bool{}
	for _, pt := range partials {
		if pt.Index < 1 || pt.Index > MaxOperators || seen[pt.Index] {
			faulty = append(faulty, pt.Index)
			continue
		}
		seen[pt.Index] = true
		els, ok := decodeElements(pt.Elements, n)
		if !ok {
			faulty = append(faulty, pt.Index)
			continue
		}
		raw, err := b64.DecodeString(pt.Proof)
		proof := new(dleq.Proof)
		if err != nil || proof.UnmarshalBinary(grp, raw) != nil ||
			!(dleq.Verifier{Params: proofParams}).VerifyBatch(grp.Generator(), b.keys.ShareKey(pt.Index), b.req.Elements, els, proof) {
			faulty = append(faulty, pt.Index)
			continue
		}
		valid = append(valid, good{pt.Index, els})
	}
	t := b.keys.Threshold()
	if len(valid) < t {
		return nil, faulty, fmt.Errorf("%w: have %d, need %d", ErrNotEnough, len(valid), t)
	}
	valid = valid[:t]

	// Lagrange coefficients at zero: l_j = prod over m != j of x_m / (x_m - x_j).
	coef := make([]group.Scalar, t)
	for j := range valid {
		xj := grp.NewScalar().SetUint64(uint64(valid[j].index))
		l := grp.NewScalar().SetUint64(1)
		for m := range valid {
			if m == j {
				continue
			}
			xm := grp.NewScalar().SetUint64(uint64(valid[m].index))
			d := grp.NewScalar().Sub(xm, xj)
			l.Mul(l, grp.NewScalar().Mul(xm, grp.NewScalar().Inv(d)))
		}
		coef[j] = l
	}
	combined := make([]group.Element, n)
	for i := range combined {
		sum := grp.Identity()
		for j := range valid {
			sum.Add(sum, grp.NewElement().Mul(valid[j].elements[i], coef[j]))
		}
		combined[i] = sum
	}
	outputs, err = oprf.NewClient(suite).Finalize(b.fin, &oprf.Evaluation{Elements: combined})
	return outputs, faulty, err
}

func decodeElement(s string) (group.Element, error) {
	raw, err := b64.DecodeString(s)
	if err != nil {
		return nil, errors.New("not base64url")
	}
	e := grp.NewElement()
	if err := e.UnmarshalBinary(raw); err != nil {
		return nil, errors.New("not a group element")
	}
	if e.IsIdentity() {
		return nil, errors.New("identity element")
	}
	return e, nil
}

func decodeElements(in []string, n int) ([]group.Element, bool) {
	if len(in) != n {
		return nil, false
	}
	out := make([]group.Element, n)
	for i, s := range in {
		e, err := decodeElement(s)
		if err != nil {
			return nil, false
		}
		out[i] = e
	}
	return out, true
}
