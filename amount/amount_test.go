package amount

import (
	"errors"
	"math/big"
	"testing"
)

func TestParse(t *testing.T) {
	valid := []string{"0", "0.5", "25.50", "1234.123456", "999999999999999999.999999"}
	for _, s := range valid {
		if _, err := Parse(s); err != nil {
			t.Errorf("Parse(%q): %v", s, err)
		}
	}
	invalid := []string{"", "-1", "+1", "01", "1.", ".5", "1.1234567", "1e3", "1,000", " 1", "1000000000000000000"}
	for _, s := range invalid {
		if _, err := Parse(s); !errors.Is(err, ErrInvalid) {
			t.Errorf("Parse(%q) = %v, want ErrInvalid", s, err)
		}
	}
}

func TestFormat(t *testing.T) {
	tests := map[string]*big.Rat{
		"0":        new(big.Rat),
		"25.5":     big.NewRat(51, 2),
		"1000":     big.NewRat(1000, 1),
		"0.000001": big.NewRat(1, 1_000_000),
	}
	for want, v := range tests {
		if got, err := Format(v); err != nil || got != want {
			t.Errorf("Format(%s) = %q, %v; want %q", v.RatString(), got, err, want)
		}
	}
	for _, v := range []*big.Rat{big.NewRat(-1, 1), big.NewRat(1, 3), big.NewRat(1, 10_000_000)} {
		if _, err := Format(v); !errors.Is(err, ErrInvalid) {
			t.Errorf("Format(%s) = %v, want ErrInvalid", v.RatString(), err)
		}
	}
}

func TestCmpComparesByValue(t *testing.T) {
	if c, err := Cmp("25.5", "25.50"); err != nil || c != 0 {
		t.Errorf("Cmp(25.5, 25.50) = %d, %v", c, err)
	}
	if c, _ := Cmp("9.99", "10"); c != -1 {
		t.Errorf("Cmp(9.99, 10) = %d", c)
	}
}

func TestMulIntIsExact(t *testing.T) {
	// 0.1 × 3 is 0.3 exactly; binary floating point would not agree.
	if got, err := MulInt("0.1", 3); err != nil || got != "0.3" {
		t.Errorf("MulInt(0.1, 3) = %q, %v", got, err)
	}
	if got, _ := MulInt("25.50", 5302114); got != "135203907" {
		t.Errorf("MulInt(25.50, 5302114) = %q", got)
	}
	if _, err := MulInt("1", -1); !errors.Is(err, ErrInvalid) {
		t.Errorf("negative multiplier: %v", err)
	}
	if _, err := MulInt("999999999999999999", 10); !errors.Is(err, ErrInvalid) {
		t.Errorf("overflow: %v", err)
	}
}
