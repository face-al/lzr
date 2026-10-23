package ldap

import (
	"encoding/hex"

	"github.com/stanford-esrg/lzr"
)

// Handshake implements the lzr.Handshake interface
type HandshakeMod struct {
}

// Anonymous root DSE read (RFC 4512, Section 5.1), messageID 1: SearchRequest
// with baseObject "", scope baseObject, filter (objectClass=*) and the
// attributes supportedLDAPVersion, supportedExtension, vendorName and
// vendorVersion. Same bytes as zgrab2's ldap module (rootDSERequest), so
// change both together. No Bind is needed, a new session is anonymous
// (RFC 4513, Section 4).
const rootDSERequest = "306a020101636504000a01000a0100020100020100010100870b6f626a656374436c617373" +
	"30450414737570706f727465644c44415056657273696f6e0412737570706f7274656445" +
	"7874656e73696f6e040a76656e646f724e616d65040d76656e646f7256657273696f6e"

func (h *HandshakeMod) GetData(dst string) []byte {
	data, _ := hex.DecodeString(rootDSERequest)
	return data
}

// Verify matches the start of an LDAPMessage (RFC 4511, Section 4.1.1) in
// the same shape as TLS-Attacker's LDAP patterns: SEQUENCE, definite length,
// messageID "02 01 xx" (minimally encoded), protocolOp tag and length. Only a prefix is checked,
// since lzr sees the first segment only. Unlike TLS-Attacker, which waits for
// SearchResultDone, a SearchResultEntry is accepted too: 389ds sends the entry
// and the done in separate segments.
func (h *HandshakeMod) Verify(data string) string {
	if len(data) < 2 || data[0] != 0x30 {
		return ""
	}
	n := lengthSize(data[1])
	if n == 0 {
		return ""
	}
	i := 1 + n
	if len(data) < i+5 || data[i] != 0x02 || data[i+1] != 0x01 {
		return ""
	}
	msgID, op := data[i+2], data[i+3]
	switch {
	case msgID == 0x01 && (op == 0x64 || op == 0x65 || op == 0x73):
		// SearchResultEntry, SearchResultDone, SearchResultReference
		// (RFC 4511, Section 4.5.2)
	case msgID == 0x00 && op == 0x78:
		// Notice of Disconnection, an unsolicited ExtendedResponse
		// (RFC 4511, Section 4.4.1)
	default:
		return ""
	}
	n = lengthSize(data[i+4])
	if n == 0 || len(data) < i+4+n {
		return ""
	}
	return "ldap"
}

func RegisterHandshake() {
	var h HandshakeMod
	lzr.AddHandshake("ldap", &h)
}

// lengthSize returns the number of octets of a BER length starting with b:
// short form, or long form with 1 to 4 length octets. The indefinite form is
// not allowed in LDAP (RFC 4511, Section 5.1); 0 means invalid.
func lengthSize(b byte) int {
	switch {
	case b < 0x80:
		return 1
	case b >= 0x81 && b <= 0x84:
		return 1 + int(b&0x7f)
	}
	return 0
}
