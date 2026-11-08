package canonical

import (
	"errors"
	"testing"
)

func TestTransform(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"whitespace removed", " { \"b\" : 1 ,\n \"a\" : [ true , false , null ] } ", `{"a":[true,false,null],"b":1}`},
		{"nested keys sorted", `{"z":{"y":1,"x":2},"a":[]}`, `{"a":[],"z":{"x":2,"y":1}}`},
		{"empty containers", `{"a":{},"b":[]}`, `{"a":{},"b":[]}`},
		{"top-level scalar", `"text"`, `"text"`},
		{"negative zero", `-0`, `0`},
		{"largest safe integers", `[9007199254740991,-9007199254740991]`, `[9007199254740991,-9007199254740991]`},
		// Escapes are rewritten in the RFC 8785 form: short escapes where
		// they exist, lowercase \u00xx for other control characters, and
		// literal UTF-8 for everything else, including "/" and U+2028.
		{"string escapes", `"\u0022\\\/\b\f\n\r\t\u0001\u001F\u00e9\u2028\ud83d\ude00"`, "\"\\\"\\\\/\\b\\f\\n\\r\\t\\u0001\\u001f\u00e9\u2028\U0001F600\""},
		// The key-sorting example from RFC 8785, section 3.2.3: keys are
		// ordered by UTF-16 code units, so the emoji (a surrogate pair
		// starting 0xD83D) sorts before U+FB33.
		{
			"RFC 8785 key ordering",
			`{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`,
			"{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Transform([]byte(tt.in))
			if err != nil {
				t.Fatalf("Transform(%s) error: %v", tt.in, err)
			}
			if string(got) != tt.want {
				t.Errorf("Transform(%s)\n got  %s\n want %s", tt.in, got, tt.want)
			}
		})
	}
}

func TestTransformRejects(t *testing.T) {
	tests := []struct {
		name, in string
		want     error
	}{
		{"fraction", `{"a":1.5}`, ErrNumber},
		{"integral fraction", `{"a":1.0}`, ErrNumber},
		{"exponent", `{"a":1e3}`, ErrNumber},
		{"too large", `9007199254740992`, ErrNumber},
		{"too small", `-9007199254740992`, ErrNumber},
		{"duplicate key", `{"a":1,"a":2}`, ErrDuplicateKey},
		{"nested duplicate key", `{"x":{"a":1,"a":1}}`, ErrDuplicateKey},
		{"invalid UTF-8", "\"\xff\"", ErrInvalidUTF8},
		{"trailing data", `{} {}`, ErrTrailingData},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Transform([]byte(tt.in))
			if !errors.Is(err, tt.want) {
				t.Errorf("Transform(%q) error = %v, want %v", tt.in, err, tt.want)
			}
		})
	}

	for _, in := range []string{``, `{`, `{"a":}`, `[1,]`} {
		if _, err := Transform([]byte(in)); err == nil {
			t.Errorf("Transform(%q) succeeded on malformed JSON", in)
		}
	}
}

func TestMarshalMatchesTransform(t *testing.T) {
	v := map[string]any{"b": []int{3, 2, 1}, "a": "x<y&z"}
	got, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	// encoding/json escapes <, > and & by default; the canonical form
	// writes them literally.
	if want := `{"a":"x<y&z","b":[3,2,1]}`; string(got) != want {
		t.Errorf("Marshal = %s, want %s", got, want)
	}
}

func TestIdempotent(t *testing.T) {
	in := `{"b":[1,{"d":null,"c":"\u00e9"}],"a":true}`
	once, err := Transform([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	twice, err := Transform(once)
	if err != nil {
		t.Fatal(err)
	}
	if string(once) != string(twice) {
		t.Errorf("canonical form changed on second pass:\n %s\n %s", once, twice)
	}
}
