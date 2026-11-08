package uniqueness

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/cloudflare/circl/oprf"
	"github.com/polycentric-commonwealth/foundation/internal/network"
	"github.com/polycentric-commonwealth/foundation/record"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRFC9497Vectors runs the RFC 9497 test vectors for the VOPRF mode of
// ristretto255-SHA512 through a one-operator configuration: the key is the
// vectors' skSm, so blinding, evaluation, proof and finalization must
// reproduce the RFC's outputs exactly.
func TestRFC9497Vectors(t *testing.T) {
	sk := grp.NewScalar()
	if err := sk.UnmarshalBinary(mustHex(t, "e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909")); err != nil {
		t.Fatal(err)
	}
	pk, _ := grp.NewElement().MulGen(sk).MarshalBinaryCompress()
	if got := hex.EncodeToString(pk); got != "c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e" {
		t.Fatalf("pkSm = %s", got)
	}
	keys, err := ParsePublicKeys([]string{b64.EncodeToString(pk)})
	if err != nil {
		t.Fatal(err)
	}
	share := Share{Index: 1, Key: sk}
	if !keys.Matches(share) {
		t.Fatal("share does not match its commitment")
	}

	vectors := []struct{ input, blind, blinded, evaluated, output string }{
		{"00", "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
			"863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945",
			"aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e",
			"b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7da4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c"},
		{"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
			"cc0b2a350101881d8a4cba4c80241d74fb7dcbfde4a61fde2f91443c2bf9ef0c",
			"60a59a57208d48aca71e9e850d22674b611f752bed48b36f7a91b372bd7ad468",
			"8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6"},
	}
	for _, v := range vectors {
		blind := grp.NewScalar()
		if err := blind.UnmarshalBinary(mustHex(t, v.blind)); err != nil {
			t.Fatal(err)
		}
		b, blinded, err := keys.blind([][]byte{mustHex(t, v.input)}, []oprf.Blind{blind})
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(must(b64.DecodeString(blinded[0]))); got != v.blinded {
			t.Errorf("blinded element = %s, want %s", got, v.blinded)
		}
		elements, proof, err := share.Evaluate(blinded)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(must(b64.DecodeString(elements[0]))); got != v.evaluated {
			t.Errorf("evaluation element = %s, want %s", got, v.evaluated)
		}
		out, faulty, err := b.Finalize([]Partial{{Index: 1, Elements: elements, Proof: proof}})
		if err != nil || len(faulty) > 0 {
			t.Fatalf("finalize: %v, faulty %v", err, faulty)
		}
		if got := hex.EncodeToString(out[0]); got != v.output {
			t.Errorf("output = %s, want %s", got, v.output)
		}
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// TestThreshold checks that any threshold of operators gives the output of
// the full key, and that a cheating operator is detected and ignored.
func TestThreshold(t *testing.T) {
	commitments, shares, err := Deal(3, 5)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParsePublicKeys(commitments)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range shares {
		if !keys.Matches(s) {
			t.Fatalf("share %d does not match the commitments", s.Index)
		}
		if back, err := ParseShare(s.String()); err != nil || !back.Key.IsEqual(s.Key) || back.Index != s.Index {
			t.Fatalf("share %d does not round-trip: %v", s.Index, err)
		}
	}

	// The full key, recovered from shares 1 to 3, evaluates directly.
	secret := grp.NewScalar()
	for j, xj := range []uint64{1, 2, 3} {
		l := grp.NewScalar().SetUint64(1)
		for _, xm := range []uint64{1, 2, 3} {
			if xm == xj {
				continue
			}
			m := grp.NewScalar().SetUint64(xm)
			l.Mul(l, grp.NewScalar().Mul(m, grp.NewScalar().Inv(grp.NewScalar().Sub(m, grp.NewScalar().SetUint64(xj)))))
		}
		secret.Add(secret, grp.NewScalar().Mul(l, shares[j].Key))
	}
	raw, _ := secret.MarshalBinary()
	priv := new(oprf.PrivateKey)
	if err := priv.UnmarshalBinary(suite, raw); err != nil {
		t.Fatal(err)
	}
	inputs := [][]byte{[]byte("alice"), []byte("bob")}
	want := make([][]byte, len(inputs))
	for i, in := range inputs {
		want[i], err = oprf.NewVerifiableServer(suite, priv).FullEvaluate(in)
		if err != nil {
			t.Fatal(err)
		}
	}

	evaluate := func(b *Blinding, blinded []string, idx ...int) []Partial {
		var ps []Partial
		for _, i := range idx {
			els, proof, err := shares[i-1].Evaluate(blinded)
			if err != nil {
				t.Fatal(err)
			}
			ps = append(ps, Partial{Index: i, Elements: els, Proof: proof})
		}
		return ps
	}

	for _, subset := range [][]int{{1, 2, 3}, {2, 4, 5}, {5, 1, 3}, {1, 2, 3, 4, 5}} {
		b, blinded, err := keys.Blind(inputs)
		if err != nil {
			t.Fatal(err)
		}
		out, faulty, err := b.Finalize(evaluate(b, blinded, subset...))
		if err != nil || len(faulty) > 0 {
			t.Fatalf("subset %v: %v, faulty %v", subset, err, faulty)
		}
		for i := range out {
			if !bytes.Equal(out[i], want[i]) {
				t.Errorf("subset %v: output %d differs from the full key's", subset, i)
			}
		}
	}

	// Operator 2 answers with operator 4's evaluation: its proof fails, it is
	// reported, and the other three still give the right outputs.
	b, blinded, _ := keys.Blind(inputs)
	ps := evaluate(b, blinded, 1, 2, 3, 4)
	ps[1].Elements = ps[3].Elements
	out, faulty, err := b.Finalize(ps)
	if err != nil {
		t.Fatal(err)
	}
	if len(faulty) != 1 || faulty[0] != 2 {
		t.Errorf("faulty = %v, want [2]", faulty)
	}
	if !bytes.Equal(out[0], want[0]) {
		t.Error("outputs are wrong with a cheating operator")
	}

	// Two honest operators are not enough.
	b, blinded, _ = keys.Blind(inputs)
	if _, _, err := b.Finalize(evaluate(b, blinded, 1, 5)); !errors.Is(err, ErrNotEnough) {
		t.Errorf("two of three: err = %v, want ErrNotEnough", err)
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"  Zoë  O'Brien-Smith ": "zoe o brien smith",
		"MÜLLER":                "muller",
		"Straße":                "strasse",
		"Ｆｕｌｌ　Ｗｉｄｔｈ":            "full width",
		"Παπαδόπουλος":          "παπαδοπουλοσ", // case folding maps final sigma to sigma
		"李 小龍":                  "李 小龍",
		"--":                    "",
	} {
		if got := NormalizeName(in); got != want {
			t.Errorf("NormalizeName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := NormalizeNumber("AB-123 456"); got != "ab123456" {
		t.Errorf("NormalizeNumber = %q", got)
	}

	a, err := NameBirth("O'Brien", "Zoë", "1990-02-28", "CA")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NameBirth("OBRIEN", "zoe", "1990-02-28", "CA")
	c, _ := NameBirth("O Brien", "Zoe", "1990-02-28", "CA")
	if bytes.Equal(a, b) || !bytes.Equal(a, c) {
		t.Error("an apostrophe separates words; case and accents do not matter")
	}
	for _, bad := range [][4]string{
		{"x", "y", "1990-02-30", "CA"},
		{"x", "y", "1990-2-3", "CA"},
		{"x", "y", "1990-02-03", "ca"},
		{"", "--", "1990-02-03", "CA"},
	} {
		if _, err := NameBirth(bad[0], bad[1], bad[2], bad[3]); err == nil {
			t.Errorf("NameBirth%v accepted", bad)
		}
	}
	r1, _ := BirthRegistration("CA", "Ontario Registrar General", "1990-123 456")
	r2, _ := BirthRegistration("CA", "ontario registrar-general", "1990123456")
	if !bytes.Equal(r1, r2) {
		t.Error("birth registration inputs should normalize equal")
	}
	if bytes.Contains(r1, []byte(KindNameBirth)) || !bytes.HasPrefix(r1, []byte("pc-uniqueness/1\x00birth-registration\x00CA\x00")) {
		t.Errorf("input = %q", r1)
	}
}

func TestIndex(t *testing.T) {
	tok := func(c byte) string { return b64.EncodeToString(bytes.Repeat([]byte{c}, 32)) }
	x := NewIndex(1)
	if c, err := x.Apply("a.example", &Registration{Epoch: 1, Add: []string{tok(1), tok(2)}}); err != nil || len(c) != 0 {
		t.Fatalf("first registration: %v %v", c, err)
	}
	c, err := x.Apply("b.example", &Registration{Epoch: 1, Add: []string{tok(2), tok(3)}})
	if err != nil || len(c) != 1 || c[0].Token != tok(2) || strings.Join(c[0].States, ",") != "a.example,b.example" {
		t.Fatalf("conflict = %+v, %v", c, err)
	}
	if err := c[0].Validate(); err != nil {
		t.Error(err)
	}
	// The person moved: a removes them and the conflict is gone.
	if _, err := x.Apply("a.example", &Registration{Epoch: 1, Remove: []string{tok(2)}}); err != nil {
		t.Fatal(err)
	}
	if h := x.Holders(tok(2)); len(h) != 1 || h[0] != "b.example" {
		t.Errorf("holders = %v", h)
	}
	if x.Count("a.example") != 1 || x.Count("b.example") != 2 {
		t.Errorf("counts = %d, %d", x.Count("a.example"), x.Count("b.example"))
	}
	if _, err := x.Apply("a.example", &Registration{Epoch: 2, Add: []string{tok(4)}}); err == nil {
		t.Error("registration for another epoch accepted")
	}
	if _, err := x.Apply("a.example", &Registration{Epoch: 1, Add: []string{tok(4), tok(4)}}); err == nil {
		t.Error("duplicate token accepted")
	}
}

// TestService runs three operators of a 2-of-3 configuration over HTTPS:
// two States compute tokens, one operator is down, one person is resident in
// both States, and the registry finds the conflict.
func TestService(t *testing.T) {
	net, err := network.Start(
		network.Spec{Instance: "commonwealth.example", Layer: record.Commonwealth, Name: "Commonwealth"},
		network.Spec{Instance: "op1.example", Layer: record.Region, Name: "Operator 1", Parent: "commonwealth.example"},
		network.Spec{Instance: "op2.example", Layer: record.Region, Name: "Operator 2", Parent: "commonwealth.example"},
		network.Spec{Instance: "op3.example", Layer: record.Region, Name: "Operator 3", Parent: "commonwealth.example"},
		network.Spec{Instance: "north.example", Layer: record.State, Name: "North", Parent: "op1.example"},
		network.Spec{Instance: "south.example", Layer: record.State, Name: "South", Parent: "op2.example"},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer net.Close()

	commitments, shares, err := Deal(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Suite: SuiteID, Epoch: 1, Commitments: commitments, Registry: "commonwealth.example",
		Operators: []Operator{{"op1.example", 1}, {"op2.example", 2}, {"op3.example", 3}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	// The configuration travels as a signed record.
	cwNode := net.Nodes["commonwealth.example"]
	cfgEnv, err := record.New("commonwealth.example", "k1", record.Commonwealth, ConfigType, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfgEnv.Sign(cwNode.Identity.Key)
	if cfg, err = DecodeConfig(cfgEnv); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	served := map[string]int{}
	for i, op := range cfg.Operators {
		node := net.Nodes[op.Instance]
		svc := &OperatorService{Self: node.Identity, Registry: node.Registry, Config: cfg, Share: shares[i],
			Allow: func(state string, n int) error {
				mu.Lock()
				defer mu.Unlock()
				served[op.Instance] += n
				return nil
			}}
		mux := http.NewServeMux()
		mux.Handle("/"+EvaluatePath, svc)
		node.Extra = mux
	}
	net.Nodes["op3.example"].Server.Close() // operator 3 is down

	people := func(names ...string) [][]byte {
		var in [][]byte
		for _, n := range names {
			b, err := NameBirth(n, "Test", "1980-01-01", "FR")
			if err != nil {
				t.Fatal(err)
			}
			in = append(in, b)
		}
		return in
	}
	tokensFor := func(state string, in [][]byte) []string {
		node := net.Nodes[state]
		c := &Client{Self: node.Identity, Registry: node.Registry, Config: cfg, HTTP: net.HTTP}
		toks, problems, err := c.Tokens(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		if len(problems) != 1 || problems[0].Instance != "op3.example" {
			t.Errorf("%s: problems = %v, want only op3", state, problems)
		}
		return toks
	}
	north := tokensFor("north.example", people("Martin", "Bernard", "Dubois"))
	south := tokensFor("south.example", people("Dubois", "Moreau"))
	if north[2] != south[0] {
		t.Fatal("the same person has different tokens in two States")
	}
	if north[0] == north[1] || !ValidToken(north[0]) {
		t.Fatal("tokens are not distinct and well-formed")
	}
	if served["op1.example"] != 5 || served["op2.example"] != 5 {
		t.Errorf("served = %v", served)
	}

	x := NewIndex(1)
	if c, _ := x.Apply("north.example", &Registration{Epoch: 1, Add: north}); len(c) != 0 {
		t.Fatalf("conflicts = %v", c)
	}
	c, err := x.Apply("south.example", &Registration{Epoch: 1, Add: south})
	if err != nil || len(c) != 1 || c[0].Token != north[2] {
		t.Fatalf("conflicts = %v, %v", c, err)
	}

	// A State's request to another epoch, or from a non-State, is refused.
	nn := net.Nodes["north.example"]
	bad := &Config{Suite: SuiteID, Epoch: 2, Commitments: commitments, Registry: "commonwealth.example", Operators: cfg.Operators[:2]}
	if _, _, err := (&Client{Self: nn.Identity, Registry: nn.Registry, Config: bad, HTTP: net.HTTP}).Tokens(context.Background(), people("X")); !errors.Is(err, ErrNotEnough) {
		t.Errorf("wrong epoch: err = %v", err)
	}
	cw := &Client{Self: cwNode.Identity, Registry: cwNode.Registry, Config: cfg, HTTP: net.HTTP}
	if _, problems, err := cw.Tokens(context.Background(), people("X")); err == nil || len(problems) != 3 ||
		!strings.Contains(problems[0].Error(), "type-not-allowed") {
		t.Errorf("commonwealth request: %v %v", problems, err)
	}
}
