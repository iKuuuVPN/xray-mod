//go:build !ipsecmb || !linux || !amd64 || !cgo

package shadowsocks

import (
	"crypto/cipher"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

func ipsecmbAvailable() bool { return false }

func matchAESGCMUserIPsecMB(_ *AESGCMUserMatcher, _ []byte) (u *protocol.MemoryUser, aead cipher.AEAD, ivLen int32, err error) {
	return nil, nil, 0, errors.New("ipsec-mb is not enabled in this build")
}
