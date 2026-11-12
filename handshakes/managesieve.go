package handshakes

import "github.com/stanford-esrg/lzr/handshakes/managesieve"

func init() {
	managesieve.RegisterHandshake()
}
