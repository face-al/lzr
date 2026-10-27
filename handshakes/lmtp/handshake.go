package lmtp

import (
	"strings"
	"unicode"
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
	// The greeting is the first line the server sends (RFC 2033, Section 4;
	// RFC 5321, Section 3.1); anything after it, such as a reply to the
	// probe or further lines of a multiline greeting, is ignored. The whole
	// line must be in this segment.
	end := strings.Index(data, "\r\n")
	if end < 0 {
		return ""
	}
	line := data[:end]
	if len(line) < 3 || !utf8.ValidString(line) || strings.ContainsAny(line, "\x00\r\n") {
		return ""
	}
	// 220 accepts commands; 4xx and 5xx (e.g. 421, 554) refuse service
	// (RFC 5321, Sections 3.1 and 4.2.3). Unlike TLS-Attacker (^220(?: |$)),
	// which needs a greeting it can go on from, refusals are accepted as they
	// still identify the service, as in the zgrab2 lmtp module.
	code := line[:3]
	refusal := (code[0] == '4' || code[0] == '5') && isDigit(code[1]) && isDigit(code[2])
	if code != "220" && !refusal {
		return ""
	}
	// The code ends the line or is followed by a space, or by "-" on the
	// first line of a multiline greeting (RFC 5321, Section 4.2), whose last
	// line TLS-Attacker (multiline find) and zgrab2 then go on from.
	if len(line) > 3 && line[3] != ' ' && line[3] != '-' {
		return ""
	}
	// An LMTP greeting looks like an SMTP one (RFC 2033, Section 4), so only
	// one that names the protocol is LMTP, e.g. "220 host Cyrus LMTP v3.8.2
	// server ready". The first word is the server's domain (RFC 5321,
	// Section 4.3.1), so a host named lmtp.example.com does not count, and
	// the rest is split at punctuation, so "(LMTP)" and "ESMTP/LMTP" do, as
	// does a later word naming an LMTP host (e.g. "lmtp-gw.example.com").
	// Dovecot greets with "220 host Dovecot ready." and is not recognized.
	words := strings.Fields(strings.TrimPrefix(line[3:], "-"))
	if len(words) < 2 {
		return ""
	}
	for _, word := range words[1:] {
		tokens := strings.FieldsFunc(word, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		})
		for _, token := range tokens {
			if strings.EqualFold(token, "lmtp") {
				return "lmtp"
			}
		}
	}
	return ""
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func RegisterHandshake() {
	var h HandshakeMod
	lzr.AddHandshake("lmtp", &h)
}
