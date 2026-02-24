//go:build ipsecmb && linux && amd64 && cgo

package shadowsocks

import (
	"crypto/cipher"

	"github.com/xtls/xray-core/common/protocol"
)

func ipsecmbAvailable() bool { return true }

func matchAESGCMUserIPsecMB(m *AESGCMUserMatcher, bs []byte) (u *protocol.MemoryUser, aead cipher.AEAD, ivLen int32, err error) {
	return m.MatchTCPIPsecMB(bs)
}
