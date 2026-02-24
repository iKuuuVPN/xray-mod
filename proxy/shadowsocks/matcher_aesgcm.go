package shadowsocks

import (
	"crypto/cipher"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// AESGCMUserMatcher extracts the SS AEAD aes-128-gcm / aes-256-gcm user matching
// flow so it can be benchmarked / optimized independently (e.g. via multi-buffer
// AES-GCM).
//
// It matches the first AEAD chunk-size block (TCP) and returns the first user
// whose key can successfully authenticate & decrypt that block.
type AESGCMUserMatcher struct {
	users      []*protocol.MemoryUser
	cipherType CipherType
	keyLen     int32
	// keysFlat stores base keys from MemoryAccount.Key, concatenated.
	// Layout: keysFlat[i*keyLen : i*keyLen+keyLen] is the i-th user key.
	keysFlat []byte
}

func aeadKeyLen(cipherType CipherType) (int32, error) {
	switch cipherType {
	case CipherType_AES_128_GCM:
		return 16, nil
	case CipherType_AES_256_GCM:
		return 32, nil
	default:
		return 0, errors.New("unexpected cipher type")
	}
}

func NewAESGCMUserMatcher(users []*protocol.MemoryUser, cipherType CipherType) (*AESGCMUserMatcher, error) {
	keyLen, err := aeadKeyLen(cipherType)
	if err != nil {
		return nil, err
	}

	keysFlat := make([]byte, len(users)*int(keyLen))
	for i, u := range users {
		account, ok := u.Account.(*MemoryAccount)
		if !ok {
			return nil, errors.New("unexpected account type")
		}
		if account.CipherType != cipherType {
			return nil, errors.New("unexpected cipher type")
		}
		if len(account.Key) != int(keyLen) {
			return nil, errors.New("unexpected key size")
		}
		copy(keysFlat[i*int(keyLen):(i+1)*int(keyLen)], account.Key)
	}

	return &AESGCMUserMatcher{
		users:      users,
		cipherType: cipherType,
		keyLen:     keyLen,
		keysFlat:   keysFlat,
	}, nil
}

// MatchTCP matches one user for a SS AEAD AES-GCM TCP session.
// bs must start with the salt/IV and be long enough to include the first
// encrypted chunk-size block (18 bytes for 2B size + 16B tag).
func (m *AESGCMUserMatcher) MatchTCP(bs []byte) (u *protocol.MemoryUser, aead cipher.AEAD, ivLen int32, err error) {
	const (
		sizeCipherTextLn = 2 + 16 // size(2) + gcm tag(16)
	)

	if len(bs) < int(m.keyLen)+sizeCipherTextLn {
		return nil, nil, 0, ErrNotFound
	}

	iv := bs[:m.keyLen]
	sizeCipherText := bs[m.keyLen : m.keyLen+sizeCipherTextLn]

	var nonce [12]byte
	var plainSize [2]byte
	var subkey [32]byte

	for i := range m.users {
		key := m.keysFlat[i*int(m.keyLen) : i*int(m.keyLen)+int(m.keyLen)]
		hkdfSHA1(key, iv, subkey[:m.keyLen])
		aead = createAesGcm(subkey[:m.keyLen])
		if _, openErr := aead.Open(plainSize[:0], nonce[:], sizeCipherText, nil); openErr == nil {
			return m.users[i], aead, m.keyLen, nil
		}
	}

	return nil, nil, 0, ErrNotFound
}
