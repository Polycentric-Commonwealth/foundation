package ledger

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

// The RFC 6962 reference leaves used by Certificate Transparency
// implementations, and the expected roots of the first n of them.
var rfcLeaves = []string{"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"}

var rfcRoots = []string{
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func leafHashes(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		if i < len(rfcLeaves) {
			b, _ := hex.DecodeString(rfcLeaves[i])
			out[i] = LeafHash(b)
		} else {
			out[i] = LeafHash([]byte(fmt.Sprintf("entry %d", i)))
		}
	}
	return out
}

func TestRFC6962Roots(t *testing.T) {
	if got := hex.EncodeToString(EmptyRoot[:]); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("empty root = %s", got)
	}
	leaves := leafHashes(len(rfcRoots))
	for n, want := range rfcRoots {
		root := RootHash(leaves[:n+1])
		if got := hex.EncodeToString(root[:]); got != want {
			t.Errorf("root of %d leaves = %s, want %s", n+1, got, want)
		}
	}
}

// TestProofsExhaustively checks every inclusion and consistency proof for
// every tree size up to 70, and that changing any proof hash breaks it.
func TestProofsExhaustively(t *testing.T) {
	const max = 70
	all := leafHashes(max)
	roots := make([]Hash, max+1)
	for n := 0; n <= max; n++ {
		roots[n] = RootHash(all[:n])
	}
	for n := uint64(1); n <= max; n++ {
		leaves := all[:n]
		for i := uint64(0); i < n; i++ {
			proof, err := InclusionProof(i, leaves)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyInclusion(i, n, leaves[i], proof, roots[n]); err != nil {
				t.Fatalf("inclusion of %d in %d: %v", i, n, err)
			}
			if err := VerifyInclusion(i, n, LeafHash([]byte("other")), proof, roots[n]); !errors.Is(err, ErrProof) {
				t.Fatalf("inclusion of wrong leaf %d in %d verified", i, n)
			}
			if n > 1 && err == nil {
				if VerifyInclusion((i+1)%n, n, leaves[i], proof, roots[n]) == nil {
					t.Fatalf("inclusion at wrong index %d in %d verified", (i+1)%n, n)
				}
			}
			for j := range proof {
				bad := append([]Hash(nil), proof...)
				bad[j][0] ^= 1
				if VerifyInclusion(i, n, leaves[i], bad, roots[n]) == nil {
					t.Fatalf("tampered inclusion proof %d in %d verified", i, n)
				}
			}
		}
		for m := uint64(0); m <= n; m++ {
			proof, err := ConsistencyProof(m, leaves)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyConsistency(m, n, roots[m], roots[n], proof); err != nil {
				t.Fatalf("consistency %d to %d: %v", m, n, err)
			}
			if m > 0 && m < n {
				forked := roots[m]
				forked[0] ^= 1
				if VerifyConsistency(m, n, forked, roots[n], proof) == nil {
					t.Fatalf("consistency %d to %d verified with a forked first root", m, n)
				}
				for j := range proof {
					bad := append([]Hash(nil), proof...)
					bad[j][0] ^= 1
					if VerifyConsistency(m, n, roots[m], roots[n], bad) == nil {
						t.Fatalf("tampered consistency proof %d to %d verified", m, n)
					}
				}
			}
		}
	}
}

func TestProofBounds(t *testing.T) {
	leaves := leafHashes(4)
	if _, err := InclusionProof(4, leaves); err == nil {
		t.Error("inclusion proof past the end succeeded")
	}
	if _, err := ConsistencyProof(5, leaves); err == nil {
		t.Error("consistency proof from a larger size succeeded")
	}
	if VerifyConsistency(4, 3, Hash{}, Hash{}, nil) == nil {
		t.Error("consistency from larger to smaller verified")
	}
	if VerifyConsistency(2, 2, Hash{1}, Hash{2}, nil) == nil {
		t.Error("equal sizes with different roots verified")
	}
}
