package shadowsocks

import (
	"crypto/cipher"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// AES128GCMUserMatcher extracts the SS AEAD aes-128-gcm user matching flow so it
// can be benchmarked / optimized independently (e.g. via multi-buffer AES-GCM).
//
// It matches the first AEAD chunk-size block (TCP) and returns the first user
// whose key can successfully authenticate & decrypt that block.
type AES128GCMUserMatcher struct {
	users []*protocol.MemoryUser
	// keysFlat stores base keys (16B) from MemoryAccount.Key, concatenated.
	// Layout: keysFlat[i*16 : i*16+16] is the i-th user key.
	keysFlat []byte
}

func NewAES128GCMUserMatcher(users []*protocol.MemoryUser) (*AES128GCMUserMatcher, error) {
	keysFlat := make([]byte, len(users)*16)
	for i, u := range users {
		account, ok := u.Account.(*MemoryAccount)
		if !ok {
			return nil, errors.New("unexpected account type")
		}
		if account.CipherType != CipherType_AES_128_GCM {
			return nil, errors.New("unexpected cipher type")
		}
		if len(account.Key) != 16 {
			return nil, errors.New("unexpected key size")
		}
		copy(keysFlat[i*16:(i+1)*16], account.Key)
	}

	return &AES128GCMUserMatcher{
		users:    users,
		keysFlat: keysFlat,
	}, nil
}

// MatchTCP matches one user for a SS AEAD aes-128-gcm TCP session.
// bs must start with the 16-byte salt/IV and be long enough to include the first
// encrypted chunk-size block (18 bytes for 2B size + 16B tag).
func (m *AES128GCMUserMatcher) MatchTCP(bs []byte) (u *protocol.MemoryUser, aead cipher.AEAD, ivLen int32, err error) {
	const (
		aes128gcmIVLen   = 16
		sizeCipherTextLn = 2 + 16 // size(2) + gcm tag(16)
	)

	if len(bs) < aes128gcmIVLen+sizeCipherTextLn {
		return nil, nil, 0, ErrNotFound
	}

	iv := bs[:aes128gcmIVLen]
	sizeCipherText := bs[aes128gcmIVLen : aes128gcmIVLen+sizeCipherTextLn]

	var nonce [12]byte
	var plainSize [2]byte
	var subkey [16]byte

	for i := range m.users {
		key := m.keysFlat[i*16 : i*16+16]
		hkdfSHA1(key, iv, subkey[:])
		aead = createAesGcm(subkey[:])
		if _, openErr := aead.Open(plainSize[:0], nonce[:], sizeCipherText, nil); openErr == nil {
			return m.users[i], aead, aes128gcmIVLen, nil
		}
	}

	return nil, nil, 0, ErrNotFound
}
