package handshakes

import "github.com/stanford-esrg/lzr/handshakes/sslv2"

func init() {
	sslv2.RegisterHandshake()
}
