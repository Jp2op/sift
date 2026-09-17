// Package sanitize protects against prompt injection via CVE descriptions and NVD data.
// All finding fields that come from external sources MUST be sanitized before
// being included in LLM prompts.
package sanitize

import (
	"strings"
	"unicode"
)

const (
	// MaxDescriptionLength is the maximum length of a sanitized CVE description.
	MaxDescriptionLength = 2000
)

// Input sanitizes a string sourced from NVD or other external sources
// before it is interpolated into an LLM prompt.
// It strips control characters, truncates to MaxDescriptionLength,
// and XML-escapes special characters to prevent prompt injection.
func Input(s string) string {
	// Step 1: Remove control characters (except newline and tab which are legitimate)
	s = stripControlChars(s)

	// Step 2: Truncate to prevent token budget abuse
	if len(s) > MaxDescriptionLength {
		s = s[:MaxDescriptionLength] + "... [truncated]"
	}

	// Step 3: XML-escape to neutralise injection attempts
	s = xmlEscape(s)

	return s
}

// WrapUntrusted wraps a sanitized string in XML delimiters that the system prompt
// instructs the model to treat as untrusted data — never as instructions.
func WrapUntrusted(s string) string {
	return "<untrusted_data>" + Input(s) + "</untrusted_data>"
}

// stripControlChars removes ASCII control characters (0x00–0x1F, 0x7F)
// except for newline (\n) and tab (\t) which are legitimate in CVE descriptions.
func stripControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1 // drop the character
		}
		return r
	}, s)
}

// xmlEscape replaces XML special characters with their entity equivalents.
func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
