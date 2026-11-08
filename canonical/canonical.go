// Package canonical serializes JSON in the form defined by the JSON
// Canonicalization Scheme (RFC 8785), restricted to the integer-only numbers
// that Commonwealth records allow.
//
// Two parties that canonicalize the same JSON value get byte-identical
// output, which is what makes signatures over JSON verifiable across
// implementations and languages.
package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxSafeInteger is the largest integer magnitude a record may contain,
// 2^53 - 1, the largest integer every common JSON implementation can
// represent exactly.
const MaxSafeInteger = 1<<53 - 1

var (
	// ErrNumber reports a number that is not an integer within
	// MaxSafeInteger, or that uses fraction or exponent notation.
	ErrNumber = errors.New("canonical: numbers must be integers with magnitude at most 2^53-1, written without fraction or exponent")

	// ErrDuplicateKey reports an object with the same member name twice.
	ErrDuplicateKey = errors.New("canonical: duplicate object key")

	// ErrInvalidUTF8 reports input that is not valid UTF-8.
	ErrInvalidUTF8 = errors.New("canonical: input is not valid UTF-8")

	// ErrTrailingData reports content after the first JSON value.
	ErrTrailingData = errors.New("canonical: unexpected data after JSON value")
)

// Marshal encodes v with encoding/json and returns its canonical form.
func Marshal(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Transform(data)
}

// Transform returns the canonical form of the JSON text in data. It rejects
// invalid UTF-8, duplicate object keys, trailing data and any number that is
// not a safe integer.
func Transform(data []byte) ([]byte, error) {
	if !utf8.Valid(data) {
		return nil, ErrInvalidUTF8
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, ErrTrailingData
	}

	var buf bytes.Buffer
	if err := writeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeValue reads one JSON value token by token, so duplicate keys can be
// detected (encoding/json silently keeps the last one).
func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("canonical: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("canonical: %w", err)
				}
				key := keyTok.(string)
				if _, dup := obj[key]; dup {
					return nil, fmt.Errorf("%w: %q", ErrDuplicateKey, key)
				}
				val, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = val
			}
			if _, err := dec.Token(); err != nil { // closing '}'
				return nil, fmt.Errorf("canonical: %w", err)
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil { // closing ']'
				return nil, fmt.Errorf("canonical: %w", err)
			}
			return arr, nil
		}
		return nil, fmt.Errorf("canonical: unexpected delimiter %q", t)
	case json.Number:
		return parseInteger(t)
	default: // string, bool or nil
		return t, nil
	}
}

func parseInteger(n json.Number) (int64, error) {
	s := string(n)
	if strings.ContainsAny(s, ".eE") {
		return 0, fmt.Errorf("%w: %s", ErrNumber, s)
	}
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil || i > MaxSafeInteger || i < -MaxSafeInteger {
		return 0, fmt.Errorf("%w: %s", ErrNumber, s)
	}
	return i, nil
}

func writeValue(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case int64:
		buf.WriteString(strconv.FormatInt(t, 10))
	case string:
		writeString(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeValue(buf, el); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := writeValue(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unsupported value type %T", v)
	}
	return nil
}

// writeString escapes s the way RFC 8785 requires: only the quote, the
// backslash and control characters are escaped; everything else is written
// as literal UTF-8.
func writeString(buf *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hex[r>>4])
				buf.WriteByte(hex[r&0xf])
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// lessUTF16 orders strings by their UTF-16 code units, as RFC 8785 requires
// for object keys.
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
