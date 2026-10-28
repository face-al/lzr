package xmpp

import (
	"fmt"
	"strings"

	"github.com/stanford-esrg/lzr"
)

// Handshake implements the lzr.Handshake interface
type HandshakeMod struct {
}

// streamOpening is TLS-Attacker's (and the zgrab2 xmpp module's) opening
// stream header; "%s" is the domain in 'to' (RFC 6120, Section 4.7.2).
const streamOpening = "<?xml version='1.0'?><stream:stream to='%s' version='1.0' xmlns='jabber:client'" +
	" xmlns:stream='http://etherx.jabber.org/streams'>"

// streamNamespace is the namespace of the stream element (RFC 6120,
// Section 4.8.1).
const streamNamespace = "http://etherx.jabber.org/streams"

// GetData opens a client-to-server stream to the target's IP address. Only a
// domain the server serves gets the stream features, but anything else still
// gets a stream header (RFC 6120, Section 4.9.1.3), followed by a
// host-unknown stream error (Section 4.9.3.6), which identifies the service
// just as well.
func (h *HandshakeMod) GetData(dst string) []byte {
	return []byte(fmt.Sprintf(streamOpening, dst))
}

// Verify matches the server's stream header (RFC 6120, Section 4.2): the
// segment starts, after optional whitespace (a byte order mark is not
// allowed, Section 11.6), with the XML declaration or the stream element, and
// holds the stream element and its namespace. Prosody and ejabberd send the
// declaration and the whole header in the first segment, also when answering
// another protocol's probe with a stream error (Section 4.9.1.2); a
// declaration alone is not accepted, as any XML service may send one. Like
// TLS-Attacker, the stream element needs the "stream" prefix, although
// Section 4.8.5 allows any. Server-to-server streams (jabber:server) match
// too. An echo of the probe does not: a server must not answer it with 'to'
// (Section 4.7.2), let alone as its first attribute.
func (h *HandshakeMod) Verify(data string) string {
	data = strings.TrimLeft(data, " \t\r\n")
	if !strings.HasPrefix(data, "<?xml") && !strings.HasPrefix(data, "<stream:stream") {
		return ""
	}
	if strings.HasPrefix(data, streamOpening[:strings.Index(streamOpening, "%s")]) {
		return ""
	}
	if !strings.Contains(data, "<stream:stream") || !strings.Contains(data, streamNamespace) {
		return ""
	}
	return "xmpp"
}

func RegisterHandshake() {
	var h HandshakeMod
	lzr.AddHandshake("xmpp", &h)
}
