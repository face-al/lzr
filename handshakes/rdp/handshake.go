package rdp

import (
	"encoding/hex"

	"github.com/stanford-esrg/lzr"
)

// Handshake implements the lzr.Handshake interface
type HandshakeMod struct {
}

func (h *HandshakeMod) GetData(dst string) []byte {

	datas := "0300002621e00000feca00436f6f6b69653a206d737473686173683d0d0a0100080001000000"

	data, _ := hex.DecodeString(datas)
	return data
}

// Verify accepts an X.224 Connection Confirm to the RDP Connection Request
// (MS-RDPBCGR 2.2.1.2): a TPKT header (version 3), an X.224 Class 0 CC
// (code 0xd0) whose length indicator covers the rest of the TPKT, and either
// no rdpNegData (servers before RDP 5.2) or an RDP_NEG_RSP / RDP_NEG_FAILURE
// (type 0x02 / 0x03, length 8). The X.224 references are not checked:
// Windows answers dst-ref feca, src-ref 1234, xrdp 0000/1234 and FreeRDP-based
// servers 0000/0000. A Siemens S7 COTP CC carries parameters (0xc0-0xc2)
// where rdpNegData would be, so it does not match.
func (h *HandshakeMod) Verify(data string) string {

	b := []byte(data)
	if len(b) < 11 || b[0] != 0x03 || b[1] != 0x00 {
		return ""
	}
	tpktLen := int(b[2])<<8 | int(b[3])
	if tpktLen > len(b) || int(b[4]) != tpktLen-5 || b[5] != 0xd0 {
		return ""
	}
	switch tpktLen {
	case 11:
		return "rdp"
	case 19:
		if (b[11] == 0x02 || b[11] == 0x03) && b[13] == 0x08 && b[14] == 0x00 {
			return "rdp"
		}
	}
	return ""
}

func RegisterHandshake() {
	var h HandshakeMod
	lzr.AddHandshake("rdp", &h)
}
