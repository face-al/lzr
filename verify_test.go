package lzr_test

import (
	"testing"

	"github.com/stanford-esrg/lzr"
	_ "github.com/stanford-esrg/lzr/handshakes"
)

func TestVerify(t *testing.T) {
	serverHello := "\x16\x03\x03\x0d\xd0\x02\x00\x00\x4d\x03\x03" +
		"0<1:08\x06\x03U\x04\x03\x131Elasticsearch security auto-configuration HTTP CA"
	cases := []struct {
		handshake, name, data, want string
	}{
		{"http", "HTTP 200", "HTTP/1.1 200 OK\r\n\r\n", "http"},
		{"http", "bare HTML", "<html><h1>hi</h1></html>", "http"},
		{"http", "TLS ServerHello naming HTTP", serverHello, ""},
		{"tls", "TLS ServerHello naming HTTP", serverHello, "tls"},
		{"smtp", "Postfix", "220 mail.example.org ESMTP Postfix\r\n", "smtp"},
		{"smtp", "multi-line greeting", "220-mail.example.org ESMTP\r\n220 ok\r\n", "smtp"},
		{"smtp", "bare code", "220\r\n", "smtp"},
		{"smtp", "neutral 220 greeting", "220 Service ready for new user.\r\n", "smtp"},
		{"smtp", "FTP greeting", "220 ProFTPD Server ready.\r\n", ""},
		{"smtp", "IMAP greeting naming smtp", "* OK smtp4dev\r\n", ""},
		{"smtp", "POP3 greeting of host smtp.*", "+OK smtp.example.org POP3 ready\r\n", ""},
		{"smtp", "ircd echoing EHLO", ":irc.example.org 421 * EHLO :Unknown command\r\n", ""},
	}
	for _, c := range cases {
		h, _ := lzr.GetHandshake(c.handshake)
		if got := h.Verify(c.data); got != c.want {
			t.Errorf("%s Verify(%s) = %q, want %q", c.handshake, c.name, got, c.want)
		}
	}
}
