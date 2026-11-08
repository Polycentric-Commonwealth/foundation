package ledger

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/polycentric-commonwealth/foundation/canonical"
	"github.com/polycentric-commonwealth/foundation/protocol"
	"github.com/polycentric-commonwealth/foundation/record"
)

// Record types defined by the ledger.
const (
	CheckpointType  = "ledger-checkpoint/1"
	CosignatureType = "ledger-cosignature/1"
)

// ErrInvalid reports a checkpoint, cosignature, evidence or entry that does
// not follow the specification.
var ErrInvalid = errors.New("ledger: invalid")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Storage holds a log's entries. Implementations must keep entries in order
// and never change or remove one.
type Storage interface {
	// Append stores an entry and its leaf hash at the next index.
	Append(entry []byte, leaf Hash) (index uint64, err error)
	// Size returns the number of entries.
	Size() (uint64, error)
	// Entry returns the entry at index.
	Entry(index uint64) ([]byte, error)
	// LeafHashes returns the leaf hashes of the first n entries.
	LeafHashes(n uint64) ([]Hash, error)
}

// MemoryStorage is Storage kept in memory, for tests and demonstrations.
type MemoryStorage struct {
	mu      sync.RWMutex
	entries [][]byte
	leaves  []Hash
}

func (m *MemoryStorage) Append(entry []byte, leaf Hash) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, append([]byte(nil), entry...))
	m.leaves = append(m.leaves, leaf)
	return uint64(len(m.entries) - 1), nil
}

func (m *MemoryStorage) Size() (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return uint64(len(m.entries)), nil
}

func (m *MemoryStorage) Entry(i uint64) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if i >= uint64(len(m.entries)) {
		return nil, errors.New("ledger: no such entry")
	}
	return m.entries[i], nil
}

func (m *MemoryStorage) LeafHashes(n uint64) ([]Hash, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if n > uint64(len(m.leaves)) {
		return nil, errors.New("ledger: size larger than log")
	}
	return append([]Hash(nil), m.leaves[:n]...), nil
}

// EntryBytes returns the form of a record stored in a log: its canonical
// JSON, including the signature.
func EntryBytes(env *record.Envelope) ([]byte, error) {
	if env.Signature == "" {
		return nil, invalid("record %s is not signed", env.ID)
	}
	data, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	return canonical.Transform(data)
}

// Checkpoint is the payload of a ledger-checkpoint/1 record.
type Checkpoint struct {
	Size uint64 `json:"size"`
	Root string `json:"root"`
}

// Cosignature is the payload of a ledger-cosignature/1 record.
type Cosignature struct {
	Origin     string `json:"origin"`
	Checkpoint string `json:"checkpoint"`
	Size       uint64 `json:"size"`
	Root       string `json:"root"`
}

// EncodeHash and DecodeHash convert hashes to and from unpadded base64url.
func EncodeHash(h Hash) string { return base64.RawURLEncoding.EncodeToString(h[:]) }

func DecodeHash(s string) (Hash, error) {
	var h Hash
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != len(h) {
		return h, invalid("hash must be %d bytes of unpadded base64url", len(h))
	}
	copy(h[:], b)
	return h, nil
}

func encodeHashes(hs []Hash) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = EncodeHash(h)
	}
	return out
}

func decodeHashes(ss []string) ([]Hash, error) {
	out := make([]Hash, len(ss))
	for i, s := range ss {
		h, err := DecodeHash(s)
		if err != nil {
			return nil, err
		}
		out[i] = h
	}
	return out, nil
}

// Log is an instance's own public ledger.
type Log struct {
	Self    protocol.Identity
	Storage Storage

	mu           sync.Mutex
	checkpoints  []*signedCheckpoint
	witnessSizes map[string]uint64
}

type signedCheckpoint struct {
	env          *record.Envelope
	cp           Checkpoint
	cosignatures map[string]*record.Envelope // by witness instance
}

// NewLog returns a log for the instance self.
func NewLog(self protocol.Identity, storage Storage) *Log {
	if storage == nil {
		storage = &MemoryStorage{}
	}
	return &Log{Self: self, Storage: storage}
}

// notLoggable lists record types that must never be logged: checkpoints and
// cosignatures describe the log itself, audit responses carry personal data
// (specs/eligibility-audit.md), and credentials, uniqueness tokens and
// evaluations concern individual people (specs/federated-identity.md).
var notLoggable = map[string]bool{
	CheckpointType:                    true,
	CosignatureType:                   true,
	"audit-response/1":                true,
	"resident-credential/1":           true,
	"uniqueness-evaluation-request/1": true,
	"uniqueness-evaluation/1":         true,
	"uniqueness-registration/1":       true,
	"uniqueness-conflict/1":           true,
}

// Append adds a record issued by this instance and signed with its current
// key, and returns its index.
func (l *Log) Append(env *record.Envelope) (uint64, error) {
	if env.Issuer != l.Self.Instance {
		return 0, invalid("a log holds only records issued by %s, not %s", l.Self.Instance, env.Issuer)
	}
	if notLoggable[env.Type] {
		return 0, invalid("%s records are never logged", env.Type)
	}
	if env.Key != l.Self.KeyID {
		return 0, invalid("record is signed with key %q, not the current key %q", env.Key, l.Self.KeyID)
	}
	if err := env.Verify(l.Self.Key.Public().(ed25519.PublicKey)); err != nil {
		return 0, err
	}
	entry, err := EntryBytes(env)
	if err != nil {
		return 0, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.Storage.Append(entry, LeafHash(entry))
}

// Checkpoint signs and returns a checkpoint of the log's current state.
func (l *Log) Checkpoint() (*record.Envelope, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	size, err := l.Storage.Size()
	if err != nil {
		return nil, err
	}
	leaves, err := l.Storage.LeafHashes(size)
	if err != nil {
		return nil, err
	}
	cp := Checkpoint{Size: size, Root: EncodeHash(RootHash(leaves))}
	env, err := record.New(l.Self.Instance, l.Self.KeyID, l.Self.Layer, CheckpointType, cp)
	if err != nil {
		return nil, err
	}
	if err := env.Sign(l.Self.Key); err != nil {
		return nil, err
	}
	l.checkpoints = append(l.checkpoints, &signedCheckpoint{env: env, cp: cp, cosignatures: map[string]*record.Envelope{}})
	return env, nil
}

// AddCosignature stores a witness's cosignature of one of this log's
// checkpoints. The caller must already have verified it (see
// VerifyCosignature); this only matches it to the checkpoint.
func (l *Log) AddCosignature(cos *record.Envelope) error {
	var c Cosignature
	if err := decodeStrict(cos, CosignatureType, &c); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, sc := range l.checkpoints {
		if sc.env.ID == c.Checkpoint {
			if c.Origin != l.Self.Instance || c.Size != sc.cp.Size || c.Root != sc.cp.Root {
				return invalid("cosignature does not match checkpoint %s", c.Checkpoint)
			}
			sc.cosignatures[cos.Issuer] = cos
			return nil
		}
	}
	return invalid("no checkpoint %s in this log", c.Checkpoint)
}

// Latest returns the most recent checkpoint and its cosignatures.
func (l *Log) Latest() (*record.Envelope, []*record.Envelope, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.checkpoints) == 0 {
		return nil, nil, false
	}
	sc := l.checkpoints[len(l.checkpoints)-1]
	return sc.env, sc.cosigs(), true
}

func (sc *signedCheckpoint) cosigs() []*record.Envelope {
	out := make([]*record.Envelope, 0, len(sc.cosignatures))
	for _, c := range sc.cosignatures {
		out = append(out, c)
	}
	return out
}

// Evidence returns evidence for the entry at index. It uses the checkpoint
// with the most cosignatures that includes the entry, and the earliest such
// checkpoint if several tie, because an earlier checkpoint proves that the
// record existed earlier.
func (l *Log) Evidence(index uint64) (*Evidence, error) {
	l.mu.Lock()
	var best *signedCheckpoint
	for _, sc := range l.checkpoints {
		if sc.cp.Size > index && (best == nil || len(sc.cosignatures) > len(best.cosignatures)) {
			best = sc
		}
	}
	var cosigs []*record.Envelope
	if best != nil {
		cosigs = best.cosigs()
	}
	l.mu.Unlock()
	if best == nil {
		return nil, invalid("no checkpoint includes entry %d yet", index)
	}

	entry, err := l.Storage.Entry(index)
	if err != nil {
		return nil, err
	}
	env, err := record.Parse(entry)
	if err != nil {
		return nil, err
	}
	proof, err := l.InclusionProof(index, best.cp.Size)
	if err != nil {
		return nil, err
	}
	return &Evidence{Record: env, Index: index, Inclusion: encodeHashes(proof), Checkpoint: best.env, Cosignatures: cosigs}, nil
}

// InclusionProof returns the proof that entry index is in the log at size.
func (l *Log) InclusionProof(index, size uint64) ([]Hash, error) {
	leaves, err := l.Storage.LeafHashes(size)
	if err != nil {
		return nil, err
	}
	return InclusionProof(index, leaves)
}

// ConsistencyProof returns the proof that the log at size first is a prefix
// of the log at size second.
func (l *Log) ConsistencyProof(first, second uint64) ([]Hash, error) {
	leaves, err := l.Storage.LeafHashes(second)
	if err != nil {
		return nil, err
	}
	return ConsistencyProof(first, leaves)
}

func decodeStrict(env *record.Envelope, typ string, v any) error {
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
