package ledger

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"
)

var (
	// ErrNeedsEvidence reports a record signed with a since-revoked key,
	// presented without ledger evidence.
	ErrNeedsEvidence = errors.New("ledger: record is signed with a revoked key and needs ledger evidence")

	// ErrTooLate reports evidence witnessed only after the signing key was
	// revoked.
	ErrTooLate = errors.New("ledger: record was not witnessed before its key was revoked")

	// ErrWitnesses reports evidence without enough valid cosignatures.
	ErrWitnesses = errors.New("ledger: not enough witness cosignatures")
)

// Evidence shows that a record was in its issuer's log at a checkpoint
// cosigned by witnesses.
type Evidence struct {
	Record       *record.Envelope   `json:"record"`
	Index        uint64             `json:"index"`
	Inclusion    []string           `json:"inclusion"`
	Checkpoint   *record.Envelope   `json:"checkpoint"`
	Cosignatures []*record.Envelope `json:"cosignatures"`
}

// WitnessPolicy is a verifier's choice of witnesses and how many of them
// must have cosigned.
type WitnessPolicy struct {
	Witnesses []string
	Threshold int
}

func (p WitnessPolicy) includes(id string) bool {
	for _, w := range p.Witnesses {
		if w == id {
			return true
		}
	}
	return false
}

// VerifyCheckpoint checks a checkpoint record against the registry and
// returns its payload and root.
func VerifyCheckpoint(reg *registry.Registry, env *record.Envelope) (*Checkpoint, Hash, error) {
	var cp Checkpoint
	if err := decodeStrict(env, CheckpointType, &cp); err != nil {
		return nil, Hash{}, err
	}
	root, err := DecodeHash(cp.Root)
	if err != nil {
		return nil, Hash{}, err
	}
	if cp.Size > 1<<53-1 {
		return nil, Hash{}, invalid("size too large")
	}
	if err := reg.Verify(env); err != nil {
		return nil, Hash{}, err
	}
	return &cp, root, nil
}

// VerifyCosignature checks that cos is a valid cosignature of the
// checkpoint record cp, and returns the time the witness signed it.
func VerifyCosignature(reg *registry.Registry, cos, cp *record.Envelope) (time.Time, error) {
	var c Cosignature
	if err := decodeStrict(cos, CosignatureType, &c); err != nil {
		return time.Time{}, err
	}
	var payload Checkpoint
	if err := decodeStrict(cp, CheckpointType, &payload); err != nil {
		return time.Time{}, err
	}
	if cos.Issuer == cp.Issuer {
		return time.Time{}, invalid("a log cannot witness itself")
	}
	if c.Origin != cp.Issuer || c.Checkpoint != cp.ID || c.Size != payload.Size || c.Root != payload.Root {
		return time.Time{}, invalid("cosignature by %s does not match the checkpoint", cos.Issuer)
	}
	if err := reg.Verify(cos); err != nil {
		return time.Time{}, err
	}
	return cos.IssuedAtTime()
}

// VerifyEvidence checks evidence against the registry and witness policy,
// and returns the witnessed time: the time by which the record is proven to
// have existed.
func VerifyEvidence(reg *registry.Registry, ev *Evidence, policy WitnessPolicy) (time.Time, error) {
	if ev == nil || ev.Record == nil || ev.Checkpoint == nil {
		return time.Time{}, invalid("evidence is incomplete")
	}
	if policy.Threshold < 1 {
		return time.Time{}, invalid("witness policy threshold must be at least 1")
	}
	if err := ev.Record.VerifyWith(reg); err != nil {
		return time.Time{}, err
	}
	if ev.Checkpoint.Issuer != ev.Record.Issuer {
		return time.Time{}, invalid("checkpoint is from %s, not the record's issuer %s", ev.Checkpoint.Issuer, ev.Record.Issuer)
	}
	cp, root, err := VerifyCheckpoint(reg, ev.Checkpoint)
	if err != nil {
		return time.Time{}, err
	}
	entry, err := EntryBytes(ev.Record)
	if err != nil {
		return time.Time{}, err
	}
	proof, err := decodeHashes(ev.Inclusion)
	if err != nil {
		return time.Time{}, err
	}
	if err := VerifyInclusion(ev.Index, cp.Size, LeafHash(entry), proof, root); err != nil {
		return time.Time{}, err
	}

	var times []time.Time
	seen := map[string]bool{}
	for _, cos := range ev.Cosignatures {
		if cos == nil || seen[cos.Issuer] || !policy.includes(cos.Issuer) {
			continue
		}
		at, err := VerifyCosignature(reg, cos, ev.Checkpoint)
		if err != nil {
			continue
		}
		seen[cos.Issuer] = true
		times = append(times, at)
	}
	if len(times) < policy.Threshold {
		return time.Time{}, fmt.Errorf("%w: %d valid of %d required", ErrWitnesses, len(times), policy.Threshold)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	return times[policy.Threshold-1], nil
}

// VerifyRecord verifies a record against the registry. If its signing key
// has since been revoked, it also requires evidence witnessed before the
// revocation (specs/public-ledger.md#revoked-keys). ev may be nil for
// records signed with keys that are not revoked.
func VerifyRecord(reg *registry.Registry, env *record.Envelope, ev *Evidence, policy WitnessPolicy) error {
	if err := env.VerifyWith(reg); err != nil {
		return err
	}
	revoked, ok := reg.RevokedAt(env.Issuer, env.Key)
	if !ok {
		return nil
	}
	if ev == nil {
		return ErrNeedsEvidence
	}
	got, err := EntryBytes(ev.Record)
	if err != nil {
		return err
	}
	want, err := EntryBytes(env)
	if err != nil {
		return err
	}
	if string(got) != string(want) {
		return invalid("evidence is for a different record")
	}
	witnessed, err := VerifyEvidence(reg, ev, policy)
	if err != nil {
		return err
	}
	if !witnessed.Before(revoked) {
		return fmt.Errorf("%w: witnessed %s, revoked %s", ErrTooLate, witnessed.Format(time.RFC3339), revoked.Format(time.RFC3339))
	}
	return nil
}
