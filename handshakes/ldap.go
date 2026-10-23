package handshakes

import "github.com/stanford-esrg/lzr/handshakes/ldap"

func init() {
	ldap.RegisterHandshake()
}
