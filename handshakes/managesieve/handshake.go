package managesieve

import (
	"strings"
	"unicode/utf8"

	"github.com/stanford-esrg/lzr"
)

// Handshake implements the lzr.Handshake interface
type HandshakeMod struct {
}

func (h *HandshakeMod) GetData(dst string) []byte {
	data := []byte("") // just wait for banner
	return data
}

func (h *HandshakeMod) Verify(data string) string {
	// The server greets with its capabilities, one per line, then OK, NO or
	// BYE (RFC 5804, Section 1.7; Section 4, response-capability). The
	// closing OK that TLS-Attacker waits for is not required, as only this
	// segment is seen. Each line counts only if it is whole here; Dovecot and
	// Cyrus write the list in one segment.
	found := false
	for {
		end := strings.Index(data, "\r\n")
		if end < 0 {
			break
		}
		line := data[:end]
		data = data[end+2:]
		name, ok := capabilityName(line)
		if !ok {
			break
		}
		// SIEVE, IMPLEMENTATION and VERSION MUST always be returned, and
		// names are case-insensitive (RFC 5804, Section 1.7). One of them is
		// required here, unlike TLS-Attacker, which already knows it speaks
		// ManageSieve; LZR must tell it from the other handshakes.
		if strings.EqualFold(name, "IMPLEMENTATION") ||
			strings.EqualFold(name, "SIEVE") ||
			strings.EqualFold(name, "VERSION") {
			found = true
		}
	}
	if found {
		return "managesieve"
	}
	return ""
}

// capabilityName returns the name of a capability line, a quoted string
// starting with a letter followed by the end of the line or a space and the
// value (RFC 5804, Section 4, single-capability), as TLS-Attacker's
// "^\"[A-Za-z]" requires; the value is not parsed. Names sent as literals,
// which the grammar allows, and escaped quotes in names are not recognized.
func capabilityName(line string) (string, bool) {
	if !utf8.ValidString(line) || strings.ContainsAny(line, "\x00\r\n") {
		return "", false
	}
	if len(line) < 3 || line[0] != '"' || !isLetter(line[1]) {
		return "", false
	}
	i := strings.IndexByte(line[2:], '"')
	if i < 0 {
		return "", false
	}
	end := i + 2
	if len(line) > end+1 && line[end+1] != ' ' {
		return "", false
	}
	return line[1:end], true
}

func isLetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func RegisterHandshake() {
	var h HandshakeMod
	lzr.AddHandshake("managesieve", &h)
}
