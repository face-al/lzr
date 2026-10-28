package nbd

import (
	"strings"

	"github.com/stanford-esrg/lzr"
)

// Handshake implements the lzr.Handshake interface
type HandshakeMod struct {
}

// Magic numbers the server's greeting starts with (NBD protocol, "Oldstyle
// negotiation" and "Newstyle negotiation"): NBDMAGIC, then IHAVEOPT
// (newstyle) or cliserv_magic (oldstyle).
const (
	nbdMagic     = "NBDMAGIC"
	optMagic     = "IHAVEOPT"
	cliservMagic = "\x00\x00\x42\x02\x81\x86\x12\x53"
)

func (h *HandshakeMod) GetData(dst string) []byte {
	data := []byte("") // just wait for the greeting
	return data
}

// Verify matches the start of the server's greeting: NBDMAGIC, then as much
// of IHAVEOPT or cliserv_magic as the segment holds; the handshake flags and
// anything after them are not checked. nbd-server (seen with 3.26) sends
// NBDMAGIC in a segment of its own, so NBDMAGIC alone is accepted. Unlike TLS-Attacker, which only
// goes on from a fixed newstyle greeting (NBDMAGIC, IHAVEOPT, flags 1 or 3),
// any NBD server is accepted, as whether it can do TLS is up to the zgrab2
// nbd module.
func (h *HandshakeMod) Verify(data string) string {
	if !strings.HasPrefix(data, nbdMagic) {
		return ""
	}
	rest := data[len(nbdMagic):]
	if len(rest) > len(optMagic) {
		rest = rest[:len(optMagic)]
	}
	if !strings.HasPrefix(optMagic, rest) && !strings.HasPrefix(cliservMagic, rest) {
		return ""
	}
	return "nbd"
}

func RegisterHandshake() {
	var h HandshakeMod
	lzr.AddHandshake("nbd", &h)
}
