package uniqueness

import (
	"regexp"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// Input kinds. A person may have a token of each kind; each kind is hashed
// with its own label, so tokens of different kinds never collide.
const (
	// KindBirthRegistration identifies a person by the country, authority
	// and number of their birth registration. Strong where it exists.
	KindBirthRegistration = "birth-registration"
	// KindNameBirth identifies a person by family name, given names, date
	// of birth and country of birth. Available for almost everyone, but two
	// different people can share it, so its conflicts are only candidates
	// for review.
	KindNameBirth = "name-birth"
)

const inputLabel = "pc-uniqueness/1"

var (
	countryPattern = regexp.MustCompile(`^[A-Z]{2}$`)
	datePattern    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	fold           = cases.Fold()
)

// NormalizeName returns the canonical form of a name or other free text:
// compatibility decomposition, accents and other combining marks removed,
// case folded, every run of characters other than letters and digits
// replaced by one space, and trimmed. "  Zoë  O'Brien-Smith" becomes
// "zoe o brien smith". Letters of every script are kept as they are; States
// MUST NOT transliterate between scripts, and SHOULD register a token for
// each script a person's name is officially recorded in.
func NormalizeName(s string) string {
	s = norm.NFKD.String(s)
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Mn, r):
			continue
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			b.WriteRune(r)
		default:
			space = true
		}
	}
	return norm.NFC.String(fold.String(b.String()))
}

// NormalizeNumber returns the canonical form of a registration number: the
// normalized name form with all spaces removed, so "AB-123 456" becomes
// "ab123456".
func NormalizeNumber(s string) string {
	return strings.ReplaceAll(NormalizeName(s), " ", "")
}

// BirthRegistration returns the OPRF input for a birth registration. Country
// is the ISO 3166-1 alpha-2 code of the country of birth.
func BirthRegistration(country, authority, number string) ([]byte, error) {
	if !countryPattern.MatchString(country) {
		return nil, invalid("country must be an ISO 3166-1 alpha-2 code")
	}
	a, n := NormalizeName(authority), NormalizeNumber(number)
	if a == "" || n == "" {
		return nil, invalid("authority and number are required")
	}
	return input(KindBirthRegistration, country, a, n), nil
}

// NameBirth returns the OPRF input for a name and birth. Date is YYYY-MM-DD
// and country is the ISO 3166-1 alpha-2 code of the country of birth.
func NameBirth(family, given, date, country string) ([]byte, error) {
	if !datePattern.MatchString(date) {
		return nil, invalid("date of birth must be YYYY-MM-DD")
	}
	if _, err := time.Parse(time.DateOnly, date); err != nil {
		return nil, invalid("date of birth is not a real date")
	}
	if !countryPattern.MatchString(country) {
		return nil, invalid("country must be an ISO 3166-1 alpha-2 code")
	}
	f, g := NormalizeName(family), NormalizeName(given)
	if f == "" && g == "" {
		return nil, invalid("a name is required")
	}
	return input(KindNameBirth, f, g, date, country), nil
}

// input joins the label, kind and fields with zero bytes, which cannot occur
// in normalized fields.
func input(kind string, fields ...string) []byte {
	return []byte(strings.Join(append([]string{inputLabel, kind}, fields...), "\x00"))
}

// Token is the public form of an OPRF output: the first 32 bytes, in
// unpadded base64url.
func Token(output []byte) string {
	return b64.EncodeToString(output[:32])
}

// ValidToken reports whether s is a well-formed token.
func ValidToken(s string) bool {
	raw, err := b64.DecodeString(s)
	return err == nil && len(raw) == 32 && b64.EncodeToString(raw) == s
}
