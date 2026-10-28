package lzr_test

import (
	"strings"
	"testing"

	"github.com/stanford-esrg/lzr"
	_ "github.com/stanford-esrg/lzr/handshakes"
)

func TestInconclusiveResponse(t *testing.T) {
	serverHello := "\x16\x03\x03\x00\x51\x02\x00\x00\x4d\x03\x03" + strings.Repeat("\x01", 32)
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"MINA NULs (ApacheDS 636, Apache FtpServer 990)", strings.Repeat("\x00", 1024), true},
		{"INN nnrpd 563", "400 Encrypted TLS connection failed\r\n", true},
		{"xrdp X.224 disconnect", "\x03\x00\x00\x09\x02\xf0\x80\x21\x80", true},
		{"nginx 443", "HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n\r\n<html><center><h1>400 Bad Request</h1></center></html>\r\n", true},
		{"Traefik 443", "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request", true},
		{"CrateDB ErrorResponse", "E\x00\x00\x00\x5eSFATAL\x00Minvalid length of startup packet\x00CXX000\x00\x00", true},
		{"HTTP 200", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", false},
		{"MongoDB HTTP reply", "HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\nIt looks like you are trying to access MongoDB over HTTP on the native driver port.\r\n", false},
		{"HTTP 400, empty reason", "HTTP/1.1 400\r\nContent-Length: 0\r\n\r\n", true},
		{"HTTP 404", "HTTP/1.1 404 Not Found\r\n\r\n", false},
		{"TLS ServerHello", serverHello, false},
		{"SMTP greeting", "220 mail.example.org ESMTP Postfix\r\n", false},
		{"IMAP greeting", "* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n", false},
		{"SSH banner", "SSH-2.0-OpenSSH_9.6\r\n", false},
	}
	for _, c := range cases {
		if got := lzr.InconclusiveResponse(c.data); got != c.want {
			t.Errorf("%s: inconclusive = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestUseFallback(t *testing.T) {
	nuls := &lzr.Packet{Data: strings.Repeat("\x00", 64)}
	bad := &lzr.Packet{Data: "HTTP/1.1 400 Bad Request\r\n\r\n"}
	hello := &lzr.Packet{Data: "\x16\x03\x03\x00\x51\x02\x00\x00\x4d\x03\x03" + strings.Repeat("\x01", 32)}
	none := &lzr.Packet{}
	cases := []struct {
		name             string
		packet, fallback *lzr.Packet
		want             *lzr.Packet
	}{
		{"no fallback", none, nil, none},
		{"conclusive last reply", hello, bad, hello},
		{"no reply at the end", none, bad, bad},
		{"inconclusive at the end", nuls, bad, bad},
		{"400 beats unknown", bad, nuls, bad},
	}
	for _, c := range cases {
		if got := lzr.UseFallback(c.packet, c.fallback); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got.Data, c.want.Data)
		}
	}
}
