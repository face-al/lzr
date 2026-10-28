package sslv2

import (
	"crypto/rand"

	"github.com/stanford-esrg/lzr"
)

// Handshake implements the lzr.Handshake interface
type HandshakeMod struct {
}

// Message and error codes of SSL 2.0 (draft-hickman-netscape-ssl-00,
// Appendix C).
const (
	mtError       = 0x00
	mtClientHello = 0x01
	mtServerHello = 0x04
	ctX509        = 0x01
)

// cipherSpecs lists all seven CIPHER-KINDs of the draft (Appendix C.4), in
// the same order as TLS-Attacker's SSL2CipherSuite.
var cipherSpecs = []byte{
	0x01, 0x00, 0x80, // SSL_CK_RC4_128_WITH_MD5
	0x02, 0x00, 0x80, // SSL_CK_RC4_128_EXPORT40_WITH_MD5
	0x03, 0x00, 0x80, // SSL_CK_RC2_128_CBC_WITH_MD5
	0x04, 0x00, 0x80, // SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
	0x05, 0x00, 0x80, // SSL_CK_IDEA_128_CBC_WITH_MD5
	0x06, 0x00, 0x40, // SSL_CK_DES_64_CBC_WITH_MD5
	0x07, 0x00, 0xc0, // SSL_CK_DES_192_EDE3_CBC_WITH_MD5
}

// GetData returns an SSL 2.0 CLIENT-HELLO (draft section 5.5.1) with version
// 2.0, all seven cipher kinds, no session id and a random 16-byte challenge,
// as TLS-Attacker's SSL2ClientHelloPreparator sends it. The record has a
// 2-byte header (section 4.1) by design: TLS-Attacker does not send 3-byte
// headers either. Version 2.0 rather than 3.x on purpose: a TLS server that
// merely accepts SSLv2-format hellos does not answer it with an SSL 2.0
// SERVER-HELLO, so only real SSL 2.0 servers do. SSL 3.0 is left to the tls
// handshake, which labels any record of version 3.0 (a ServerHello, but also
// an alert of a stack that rejects the hello) as "ssl".
func (h *HandshakeMod) GetData(dst string) []byte {
	challenge := make([]byte, 16)
	rand.Read(challenge)
	bodyLen := 9 + len(cipherSpecs) + len(challenge)
	data := []byte{
		0x80 | byte(bodyLen>>8), byte(bodyLen), // 2-byte header, no padding
		mtClientHello,
		0x00, 0x02, // CLIENT-VERSION
		0x00, byte(len(cipherSpecs)), // CIPHER-SPECS-LENGTH
		0x00, 0x00, // SESSION-ID-LENGTH
		0x00, byte(len(challenge)), // CHALLENGE-LENGTH
	}
	data = append(data, cipherSpecs...)
	return append(data, challenge...)
}

// Verify matches an SSL 2.0 SERVER-HELLO or ERROR record. Record header
// (section 4.1): with the high bit of the first byte set, a 2-byte header
// and a 15-bit length; else a 3-byte header with a 14-bit length, where the
// escape bit must be clear and the padding 0 (no padding in the clear). As
// the first segment may end before a large certificate does, only the 11
// fixed bytes of a SERVER-HELLO (section 5.6.1) are checked: SESSION-ID-HIT 0
// (no session id was sent), CERTIFICATE-TYPE X.509, SERVER-VERSION 2.0,
// lengths that fit the cipher specs and connection id rules and add up to the
// record length. An ERROR (section 5.7.1) is accepted with one of the four
// defined error codes, never 0, which OpenSSL sends for non-hello input: it
// shows the service speaks SSL 2.0 (e.g. no common cipher), though
// TLS-Attacker has no ERROR message, so TLS-Scanner does not report such a
// server as supporting SSL 2.0.
func (h *HandshakeMod) Verify(data string) string {
	if len(data) < 2 {
		return ""
	}
	var hdr, recLen int
	if data[0]&0x80 != 0 {
		hdr = 2
		recLen = int(data[0]&0x7f)<<8 | int(data[1])
	} else {
		if len(data) < 3 || data[0]&0x40 != 0 || data[2] != 0 {
			return ""
		}
		hdr = 3
		recLen = int(data[0]&0x3f)<<8 | int(data[1])
	}
	body := data[hdr:]
	if len(body) == 0 {
		return ""
	}
	switch body[0] {
	case mtServerHello:
		if len(body) < 11 || body[1] != 0 || body[2] != ctX509 ||
			body[3] != 0x00 || body[4] != 0x02 {
			return ""
		}
		certLen := int(body[5])<<8 | int(body[6])
		specsLen := int(body[7])<<8 | int(body[8])
		connIDLen := int(body[9])<<8 | int(body[10])
		if certLen == 0 || specsLen == 0 || specsLen%3 != 0 ||
			connIDLen < 16 || connIDLen > 32 ||
			11+certLen+specsLen+connIDLen != recLen {
			return ""
		}
		return "sslv2"
	case mtError:
		if recLen != 3 || len(body) < 3 || body[1] != 0x00 {
			return ""
		}
		switch body[2] {
		case 0x01, 0x02, 0x04, 0x06: // NO-CIPHER, NO-CERTIFICATE, BAD-CERTIFICATE, UNSUPPORTED-CERTIFICATE-TYPE
			return "sslv2"
		}
	}
	return ""
}

func RegisterHandshake() {
	var h HandshakeMod
	lzr.AddHandshake("sslv2", &h)
}
