package verdifaxmcp

import (
	"regexp"
	"sort"
	"strings"
)

// Text cleaning and redaction. Every string and key in every answer passes
// through Redactor.Value: characters in the contract's remove ranges are
// dropped, tab, line breaks and the Unicode line and paragraph separators
// become a space, and then every configured secret is replaced. Cleaning
// runs before redaction, so a secret split by a hidden character is still
// caught.

var lineSeparators = [][2]rune{{0x2028, 0x2029}}

func inRanges(r rune, ranges [][2]rune) bool {
	for _, span := range ranges {
		if r >= span[0] && r <= span[1] {
			return true
		}
	}
	return false
}

// CleanString is the string with hidden characters removed and line breaks
// as spaces.
func CleanString(text string) string {
	var b strings.Builder
	for _, r := range text {
		switch {
		case inRanges(r, contract.Implementation.TextCleaning.ReplaceWithSpace):
			b.WriteByte(' ')
		case inRanges(r, contract.Implementation.TextCleaning.Remove):
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// hasRefusedCharacter reports whether seal_decision must refuse the string.
// Tab, line feed and carriage return are allowed.
func hasRefusedCharacter(text string) bool {
	for _, r := range text {
		if inRanges(r, contract.Implementation.TextCleaning.Remove) || inRanges(r, lineSeparators) {
			return true
		}
	}
	return false
}

// Redactor hides every configured secret.
type Redactor struct {
	secrets     []string
	pattern     *regexp.Regexp
	replacement string
}

// NewRedactor hides each secret of at least 8 characters, longest first.
func NewRedactor(secrets []string) *Redactor {
	seen := map[string]bool{}
	var kept []string
	for _, s := range secrets {
		if len(s) >= 8 && !seen[s] {
			seen[s] = true
			kept = append(kept, s)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return len(kept[i]) > len(kept[j]) })
	return &Redactor{
		secrets:     kept,
		pattern:     regexp.MustCompile(contract.Implementation.Redaction.Pattern),
		replacement: contract.Implementation.Redaction.Replacement,
	}
}

func (r *Redactor) redact(text string) string {
	for _, s := range r.secrets {
		text = strings.ReplaceAll(text, s, r.replacement)
	}
	return r.pattern.ReplaceAllString(text, r.replacement)
}

// Text cleans, then redacts, one string.
func (r *Redactor) Text(value string) string { return r.redact(CleanString(value)) }

// Value is a copy of a decoded JSON value with every string and key cleaned
// and redacted.
func (r *Redactor) Value(v any) any {
	switch x := v.(type) {
	case string:
		return r.Text(x)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = r.Value(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, item := range x {
			out[r.Text(k)] = r.Value(item)
		}
		return out
	default:
		return v
	}
}
