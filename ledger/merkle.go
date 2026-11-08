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

// RootHash returns the Merkle tree hash of the given leaf hashes (RFC 9162,
// section 2.1.1).
func RootHash(leaves []Hash) Hash {
	switch len(leaves) {
	case 0:
		return EmptyRoot
	case 1:
		return leaves[0]
	}
	k := split(uint64(len(leaves)))
	return nodeHash(RootHash(leaves[:k]), RootHash(leaves[k:]))
}

// InclusionProof returns the audit path for leaf index m in a tree of the
// given leaves (RFC 9162, section 2.1.3.1).
func InclusionProof(m uint64, leaves []Hash) ([]Hash, error) {
	if m >= uint64(len(leaves)) {
		return nil, errors.New("ledger: index out of range")
	}
	return path(m, leaves), nil
}

func path(m uint64, leaves []Hash) []Hash {
	n := uint64(len(leaves))
	if n <= 1 {
		return nil
	}
	k := split(n)
	if m < k {
		return append(path(m, leaves[:k]), RootHash(leaves[k:]))
	}
	return append(path(m-k, leaves[k:]), RootHash(leaves[:k]))
}

// ConsistencyProof returns the proof that the tree of the first m leaves is
// a prefix of the tree of all leaves (RFC 9162, section 2.1.4.1).
func ConsistencyProof(m uint64, leaves []Hash) ([]Hash, error) {
	n := uint64(len(leaves))
	if m > n {
		return nil, errors.New("ledger: first size larger than second")
	}
	if m == 0 || m == n {
		return nil, nil
	}
	return subproof(m, leaves, true), nil
}

func subproof(m uint64, leaves []Hash, complete bool) []Hash {
	n := uint64(len(leaves))
	if m == n {
		if complete {
			return nil
		}
		return []Hash{RootHash(leaves)}
	}
	k := split(n)
	if m <= k {
		return append(subproof(m, leaves[:k], complete), RootHash(leaves[k:]))
	}
	return append(subproof(m-k, leaves[k:], false), RootHash(leaves[:k]))
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
