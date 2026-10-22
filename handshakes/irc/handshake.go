package irc

import (
	"strings"
	"unicode/utf8"

	"github.com/stanford-esrg/lzr"
)

// Handshake implements the lzr.Handshake interface
type HandshakeMod struct {
}

func (h *HandshakeMod) GetData(dst string) []byte {
	// IRCv3 capability negotiation rather than NICK/USER: it does not
	// register a user, gets a single reply, and wakes servers that stay
	// silent until the client speaks (e.g. UnrealIRCd). Servers that greet
	// first still send their NOTICE as the first segment.
	data := []byte("CAP LS 302\r\n")
	return data
}

func (h *HandshakeMod) Verify(data string) string {
	if data == "" || !isASCII(data) {
		return ""
	}
	// Messages a server sends without a prefix before registration
	if strings.HasPrefix(data, "NOTICE AUTH :") || strings.HasPrefix(data, "NOTICE * :") ||
		strings.HasPrefix(data, "PING :") || strings.HasPrefix(data, "ERROR :") {
		return "irc"
	}
	// ":<server> <command> ..." (RFC 2812, Section 2.3.1)
	if !strings.HasPrefix(data, ":") {
		return ""
	}
	fields := strings.SplitN(data, " ", 3)
	if len(fields) < 3 || len(fields[0]) < 2 {
		return ""
	}
	command := fields[1]
	switch {
	case command == "NOTICE", command == "CAP", command == "PING", command == "ERROR":
		return "irc"
	case isNumeric(command):
		// three-digit numeric reply (RFC 2812, Section 2.4)
		return "irc"
	}
	return ""
}

func RegisterHandshake() {
	var h HandshakeMod
	lzr.AddHandshake("irc", &h)
}

func isNumeric(s string) bool {
	if len(s) != 3 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
