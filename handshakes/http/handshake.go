package http

import (
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/stanford-esrg/lzr"
)

// Handshake implements the lzr.Handshake interface
type HandshakeMod struct {
}

func (h *HandshakeMod) GetData(dst string) []byte {

	req, _ := http.NewRequest("GET", "/", nil)
	req.Host = dst
	if lzr.IPv6Enabled() {
		req.Header.Add("Host", "["+dst+"]")
	} else {
		req.Header.Add("Host", dst)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.3")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip")
	data, _ := httputil.DumpRequest(req, false)
	return data
}

func (h *HandshakeMod) Verify(data string) string {
	// an SSL 2.0 SERVER-HELLO record (2- or 3-byte header; type 4,
	// SESSION-ID-HIT 0, X.509, version 2.0), whose certificate may name
	// HTTP, is not an HTTP response
	if (len(data) >= 7 && data[0]&0x80 != 0 && data[2:7] == "\x04\x00\x01\x00\x02") ||
		(len(data) >= 8 && data[0]&0xc0 == 0 && data[2] == 0 && data[3:8] == "\x04\x00\x01\x00\x02") {
		return ""
	}

	if !strings.Contains(data, "HTTPS") &&
		(strings.Contains(data, "HTTP") || strings.Contains(data, "html") ||
			strings.Contains(data, "HTML") || strings.Contains(data, "<h1>")) {
		return "http"
	}
	return ""

}

func RegisterHandshake() {
	var h HandshakeMod
	lzr.AddHandshake("http", &h)
}
