package shadowsocks

import (
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"hash/crc64"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

// Validator stores valid Shadowsocks users.
type Validator struct {
	sync.RWMutex
	users []*protocol.MemoryUser

	behaviorSeed  uint64
	behaviorFused bool

	useIPSecMB       bool
	aesgcmCipherType CipherType
	aesgcmMatch      *AESGCMUserMatcher
}

var ErrNotFound = errors.New("Not Found")

// Add a Shadowsocks user.
func (v *Validator) Add(u *protocol.MemoryUser) error {
	v.Lock()
	defer v.Unlock()

	account := u.Account.(*MemoryAccount)
	if !account.Cipher.IsAEAD() && len(v.users) > 0 {
		return errors.New("The cipher is not support Single-port Multi-user")
	}
	if v.useIPSecMB {
		if account.CipherType != v.aesgcmCipherType {
			return errors.New("ipsec-mb user matcher requires consistent AES-GCM cipher type")
		}
		keyLen, err := aeadKeyLen(account.CipherType)
		if err != nil {
			return err
		}
		if len(account.Key) != int(keyLen) {
			return errors.New("unexpected key size")
		}
		v.aesgcmMatch = nil
	}
	v.users = append(v.users, u)

	if !v.behaviorFused {
		hashkdf := hmac.New(sha256.New, []byte("SSBSKDF"))
		hashkdf.Write(account.Key)
		v.behaviorSeed = crc64.Update(v.behaviorSeed, crc64.MakeTable(crc64.ECMA), hashkdf.Sum(nil))
	}

	return nil
}

// Del a Shadowsocks user with a non-empty Email.
func (v *Validator) Del(email string) error {
	if email == "" {
		return errors.New("Email must not be empty.")
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	idx := -1
	for i, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			idx = i
			break
		}
	}

	if idx == -1 {
		return errors.New("User ", email, " not found.")
	}
	ulen := len(v.users)

	v.users[idx] = v.users[ulen-1]
	v.users[ulen-1] = nil
	v.users = v.users[:ulen-1]
	if v.useIPSecMB {
		v.aesgcmMatch = nil
	}

	return nil
}

// GetByEmail Get a Shadowsocks user with a non-empty Email.
func (v *Validator) GetByEmail(email string) *protocol.MemoryUser {
	if email == "" {
		return nil
	}

	v.Lock()
	defer v.Unlock()

	email = strings.ToLower(email)
	for _, u := range v.users {
		if strings.EqualFold(u.Email, email) {
			return u
		}
	}
	return nil
}

// GetAll get all users
func (v *Validator) GetAll() []*protocol.MemoryUser {
	v.Lock()
	defer v.Unlock()
	dst := make([]*protocol.MemoryUser, len(v.users))
	copy(dst, v.users)
	return dst
}

// GetCount get users count
func (v *Validator) GetCount() int64 {
	v.Lock()
	defer v.Unlock()
	return int64(len(v.users))
}

func (v *Validator) EnableIPSecMB() error {
	v.Lock()
	defer v.Unlock()

	if !ipsecmbAvailable() {
		return errors.New("ipsec-mb is not enabled in this build")
	}

	if len(v.users) == 0 {
		return errors.New("no users")
	}

	firstAccount := v.users[0].Account.(*MemoryAccount)
	cipherType := firstAccount.CipherType
	if cipherType != CipherType_AES_128_GCM && cipherType != CipherType_AES_256_GCM {
		return errors.New("ipsec-mb user matcher requires aes-128-gcm or aes-256-gcm")
	}
	keyLen, err := aeadKeyLen(cipherType)
	if err != nil {
		return err
	}

	for _, user := range v.users {
		account := user.Account.(*MemoryAccount)
		if account.CipherType != cipherType {
			return errors.New("ipsec-mb user matcher requires consistent AES-GCM cipher type")
		}
		if len(account.Key) != int(keyLen) {
			return errors.New("unexpected key size")
		}
	}

	matcher, err := NewAESGCMUserMatcher(v.users, cipherType)
	if err != nil {
		return err
	}

	v.useIPSecMB = true
	v.aesgcmCipherType = cipherType
	v.aesgcmMatch = matcher
	return nil
}

func (v *Validator) getAESGCMMatcher() (*AESGCMUserMatcher, error) {
	v.RLock()
	enabled := v.useIPSecMB
	matcher := v.aesgcmMatch
	v.RUnlock()
	if !enabled {
		return nil, nil
	}
	if matcher != nil {
		return matcher, nil
	}

	v.Lock()
	defer v.Unlock()
	if !v.useIPSecMB {
		return nil, nil
	}
	if v.aesgcmMatch != nil {
		return v.aesgcmMatch, nil
	}

	matcher, err := NewAESGCMUserMatcher(v.users, v.aesgcmCipherType)
	if err != nil {
		return nil, err
	}
	v.aesgcmMatch = matcher
	return matcher, nil
}

// Get a Shadowsocks user.
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	if command == protocol.RequestCommandTCP {
		matcher, matcherErr := v.getAESGCMMatcher()
		if matcherErr != nil {
			return nil, nil, nil, 0, matcherErr
		}
		if matcher != nil {
			u, aead, ivLen, err = matchAESGCMUserIPsecMB(matcher, bs)
			if err != nil {
				return nil, nil, nil, 0, err
			}
			return u, aead, nil, ivLen, nil
		}
	}

	v.RLock()
	defer v.RUnlock()

	for _, user := range v.users {
		if account := user.Account.(*MemoryAccount); account.Cipher.IsAEAD() {
			aeadCipher := account.Cipher.(*AEADCipher)
			ivLen = aeadCipher.IVSize()
			if len(bs) < int(ivLen)+16 {
				continue
			}
			iv := bs[:ivLen]
			subkey := make([]byte, 32)
			subkey = subkey[:aeadCipher.KeyBytes]
			hkdfSHA1(account.Key, iv, subkey)
			aead = aeadCipher.AEADAuthCreator(subkey)

			var matchErr error
			switch command {
			case protocol.RequestCommandTCP:
				if len(bs) < int(ivLen)+18 {
					continue
				}
				data := make([]byte, 4+aead.NonceSize())
				ret, matchErr = aead.Open(data[:0], data[4:], bs[ivLen:ivLen+18], nil)
			case protocol.RequestCommandUDP:
				data := make([]byte, 8192)
				ret, matchErr = aead.Open(data[:0], data[8192-aead.NonceSize():8192], bs[ivLen:], nil)
			}

			if matchErr == nil {
				u = user
				return
			}
		} else {
			u = user
			ivLen = user.Account.(*MemoryAccount).Cipher.IVSize()
			// err = user.Account.(*MemoryAccount).CheckIV(bs[:ivLen]) // The IV size of None Cipher is 0.
			return
		}
	}

	return nil, nil, nil, 0, ErrNotFound
}

func (v *Validator) GetBehaviorSeed() uint64 {
	v.Lock()
	defer v.Unlock()

	v.behaviorFused = true
	if v.behaviorSeed == 0 {
		v.behaviorSeed = dice.RollUint64()
	}
	return v.behaviorSeed
}
