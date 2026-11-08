// Package amount handles the decimal amounts used in records: non-negative
// decimal strings with up to 18 digits before the point and 6 after, such as
// "1234.56". Arithmetic is exact; amounts are compared by value, so "25.5"
// and "25.50" are equal.
package amount

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// ErrInvalid reports a string that is not a valid amount, or a result that
// cannot be written as one.
var ErrInvalid = errors.New("amount: must be a non-negative decimal with up to 18 digits before the point and 6 after")

var pattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})(\.[0-9]{1,6})?$`)

var micro = big.NewRat(1_000_000, 1)

// Parse returns the exact value of an amount string.
func Parse(s string) (*big.Rat, error) {
	if !pattern.MatchString(s) {
		return nil, fmt.Errorf("%w: %q", ErrInvalid, s)
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrInvalid, s)
	}
	return r, nil
}

// Format writes v in its shortest amount form, without trailing zeros. It
// fails if v is negative, has more than 6 decimal places or is too large.
func Format(v *big.Rat) (string, error) {
	if v.Sign() < 0 || !new(big.Rat).Mul(v, micro).IsInt() {
		return "", fmt.Errorf("%w: %s", ErrInvalid, v.RatString())
	}
	s := v.FloatString(6)
	s = strings.TrimRight(s, "0")
	s = strings.TrimSuffix(s, ".")
	if !pattern.MatchString(s) {
		return "", fmt.Errorf("%w: %s", ErrInvalid, s)
	}
	return s, nil
}

// Cmp compares two amounts by value, returning -1, 0 or +1.
func Cmp(a, b string) (int, error) {
	x, err := Parse(a)
	if err != nil {
		return 0, err
	}
	y, err := Parse(b)
	if err != nil {
		return 0, err
	}
	return x.Cmp(y), nil
}

// MulInt returns a × n, for a non-negative count n.
func MulInt(a string, n int64) (string, error) {
	x, err := Parse(a)
	if err != nil {
		return "", err
	}
	if n < 0 {
		return "", fmt.Errorf("%w: negative multiplier %d", ErrInvalid, n)
	}
	return Format(new(big.Rat).Mul(x, new(big.Rat).SetInt64(n)))
}
