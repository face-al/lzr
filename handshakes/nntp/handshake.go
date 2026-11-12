package nntp

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
	// The greeting is the first line the server sends (RFC 3977, Section 5.1.2);
	// anything after it, such as a reply to the probe, is ignored. The whole
	// line must be in this segment; it is at most 512 octets (Section 3.1).
	end := strings.Index(data, "\r\n")
	if end < 0 {
		return ""
	}
	line := data[:end]
	if len(line) < 3 || !utf8.ValidString(line) || strings.ContainsAny(line, "\x00\r\n") {
		return ""
	}
	// 200 and 201 accept commands; 400 and 502 refuse service and close.
	// These are the only valid greetings (RFC 3977, Section 5.1.1). Unlike
	// TLS-Attacker (^20[01] ), which needs a greeting it can go on from, 400
	// and 502 are accepted as they still identify the service, as in the
	// zgrab2 nntp module. Any other line protocol greeting with one of these
	// codes alone (e.g. "400 Bad Request") is labelled nntp too.
	switch line[:3] {
	case "200", "201", "400", "502":
	default:
		return ""
	}
	// The code ends the line or is followed by a space (RFC 3977, Section
	// 9.4.1); TLS-Attacker requires the space.
	if len(line) > 3 && line[3] != ' ' {
		return ""
	}
	// An implicit TLS port (nntps, 563) of INN answers a plaintext probe with
	// "400 Encrypted TLS connection failed": TLS, not STARTTLS NNTP.
	if line[:3] == "400" && strings.Contains(strings.ToUpper(line), "TLS") {
		return ""
	}
	return "nntp"
}

func RegisterHandshake() {
	var h HandshakeMod
	lzr.AddHandshake("nntp", &h)
}
