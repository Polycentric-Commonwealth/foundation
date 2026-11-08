// Package ledger implements the public ledger: per-instance append-only
// logs built as RFC 9162 Merkle trees, signed checkpoints, witness
// cosigning, and evidence that a record existed by a point in time
// (specs/public-ledger.md).
package ledger

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/bits"
)

// Hash is a SHA-256 hash of a leaf or a subtree.
type Hash [sha256.Size]byte

// ErrProof reports an inclusion or consistency proof that does not verify.
var ErrProof = errors.New("ledger: proof does not verify")

// EmptyRoot is the root hash of a log with no entries.
var EmptyRoot = Hash(sha256.Sum256(nil))

// LeafHash returns the hash of one log entry: SHA-256(0x00 || entry).
func LeafHash(entry []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(entry)
	var out Hash
	h.Sum(out[:0])
	return out
}

// nodeHash returns SHA-256(0x01 || left || right).
func nodeHash(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(left[:])
	h.Write(right[:])
	var out Hash
	h.Sum(out[:0])
	return out
}

// split returns the largest power of two smaller than n, for n > 1.
func split(n uint64) uint64 {
	return 1 << (bits.Len64(n-1) - 1)
}

// Tree holds every perfect subtree hash of a list of leaves, so the root and
// any proof can be computed in logarithmic time after one linear pass.
type Tree struct {
	levels [][]Hash // levels[k][i] is the hash of leaves [i·2^k, (i+1)·2^k)
	size   uint64
}

// NewTree builds the tree over the given leaf hashes.
func NewTree(leaves []Hash) *Tree {
	t := &Tree{levels: [][]Hash{leaves}, size: uint64(len(leaves))}
	for level := leaves; len(level) > 1; {
		next := make([]Hash, len(level)/2)
		for i := range next {
			next[i] = nodeHash(level[2*i], level[2*i+1])
		}
		t.levels = append(t.levels, next)
		level = next
	}
	return t
}

// Size returns the number of leaves.
func (t *Tree) Size() uint64 { return t.size }

// Root returns the Merkle tree hash (RFC 9162, section 2.1.1).
func (t *Tree) Root() Hash {
	if t.size == 0 {
		return EmptyRoot
	}
	return t.hash(0, t.size)
}

// hash returns the hash of the n leaves starting at start, where the range
// is a subtree of the RFC 9162 tree.
func (t *Tree) hash(start, n uint64) Hash {
	if n&(n-1) == 0 && start%n == 0 {
		return t.levels[bits.TrailingZeros64(n)][start/n]
	}
	k := split(n)
	return nodeHash(t.hash(start, k), t.hash(start+k, n-k))
}

// InclusionProof returns the audit path for leaf index m (RFC 9162, section
// 2.1.3.1).
func (t *Tree) InclusionProof(m uint64) ([]Hash, error) {
	if m >= t.size {
		return nil, errors.New("ledger: index out of range")
	}
	return t.path(m, 0, t.size), nil
}

func (t *Tree) path(m, start, n uint64) []Hash {
	if n <= 1 {
		return nil
	}
	k := split(n)
	if m < k {
		return append(t.path(m, start, k), t.hash(start+k, n-k))
	}
	return append(t.path(m-k, start+k, n-k), t.hash(start, k))
}

// ConsistencyProof returns the proof that the tree of the first m leaves is
// a prefix of this tree (RFC 9162, section 2.1.4.1).
func (t *Tree) ConsistencyProof(m uint64) ([]Hash, error) {
	if m > t.size {
		return nil, errors.New("ledger: first size larger than second")
	}
	if m == 0 || m == t.size {
		return nil, nil
	}
	return t.subproof(m, 0, t.size, true), nil
}

func (t *Tree) subproof(m, start, n uint64, complete bool) []Hash {
	if m == n {
		if complete {
			return nil
		}
		return []Hash{t.hash(start, n)}
	}
	k := split(n)
	if m <= k {
		return append(t.subproof(m, start, k, complete), t.hash(start+k, n-k))
	}
	return append(t.subproof(m-k, start+k, n-k, false), t.hash(start, k))
}

// RootHash returns the Merkle tree hash of the given leaf hashes.
func RootHash(leaves []Hash) Hash { return NewTree(leaves).Root() }

// InclusionProof returns the audit path for leaf index m in a tree of the
// given leaves. To compute many proofs over the same leaves, use a Tree.
func InclusionProof(m uint64, leaves []Hash) ([]Hash, error) {
	return NewTree(leaves).InclusionProof(m)
}

// ConsistencyProof returns the proof that the tree of the first m leaves is
// a prefix of the tree of all leaves.
func ConsistencyProof(m uint64, leaves []Hash) ([]Hash, error) {
	return NewTree(leaves).ConsistencyProof(m)
}

// VerifyInclusion checks that leaf is at index in a tree of the given size
// and root (RFC 9162, section 2.1.3.2).
func VerifyInclusion(index, size uint64, leaf Hash, proof []Hash, root Hash) error {
	if index >= size {
		return ErrProof
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return ErrProof
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || r != root {
		return ErrProof
	}
	return nil
}

// VerifyConsistency checks that a tree of size first with root firstRoot is
// a prefix of a tree of size second with root secondRoot (RFC 9162, section
// 2.1.4.2).
func VerifyConsistency(first, second uint64, firstRoot, secondRoot Hash, proof []Hash) error {
	switch {
	case first > second:
		return ErrProof
	case first == second:
		if len(proof) != 0 || firstRoot != secondRoot {
			return ErrProof
		}
		return nil
	case first == 0:
		if len(proof) != 0 {
			return ErrProof
		}
		return nil
	case len(proof) == 0:
		return ErrProof
	}

	if first&(first-1) == 0 { // first is a power of two
		proof = append([]Hash{firstRoot}, proof...)
	}
	fn, sn := first-1, second-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return ErrProof
		}
		if fn&1 == 1 || fn == sn {
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || !bytes.Equal(fr[:], firstRoot[:]) || sr != secondRoot {
		return ErrProof
	}
	return nil
}
