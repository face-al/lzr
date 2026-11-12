package handshakes

import "github.com/stanford-esrg/lzr/handshakes/lmtp"

func init() {
	lmtp.RegisterHandshake()
}
