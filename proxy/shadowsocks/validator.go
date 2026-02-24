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

	useIPSecMB     bool
	aes128gcmMatch *AES128GCMUserMatcher
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
		if account.CipherType != CipherType_AES_128_GCM {
			return errors.New("ipsec-mb user matcher requires aes-128-gcm")
		}
		if len(account.Key) != 16 {
			return errors.New("unexpected key size")
		}
		v.aes128gcmMatch = nil
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
		v.aes128gcmMatch = nil
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

	for _, user := range v.users {
		account := user.Account.(*MemoryAccount)
		if account.CipherType != CipherType_AES_128_GCM {
			return errors.New("ipsec-mb user matcher requires aes-128-gcm")
		}
		if len(account.Key) != 16 {
			return errors.New("unexpected key size")
		}
	}

	matcher, err := NewAES128GCMUserMatcher(v.users)
	if err != nil {
		return err
	}

	v.useIPSecMB = true
	v.aes128gcmMatch = matcher
	return nil
}

func (v *Validator) getAES128GCMMatcher() (*AES128GCMUserMatcher, error) {
	v.RLock()
	enabled := v.useIPSecMB
	matcher := v.aes128gcmMatch
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
	if v.aes128gcmMatch != nil {
		return v.aes128gcmMatch, nil
	}

	matcher, err := NewAES128GCMUserMatcher(v.users)
	if err != nil {
		return nil, err
	}
	v.aes128gcmMatch = matcher
	return matcher, nil
}

// Get a Shadowsocks user.
func (v *Validator) Get(bs []byte, command protocol.RequestCommand) (u *protocol.MemoryUser, aead cipher.AEAD, ret []byte, ivLen int32, err error) {
	if command == protocol.RequestCommandTCP {
		matcher, matcherErr := v.getAES128GCMMatcher()
		if matcherErr != nil {
			return nil, nil, nil, 0, matcherErr
		}
		if matcher != nil {
			u, aead, ivLen, err = matchAES128GCMUserIPsecMB(matcher, bs)
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
			// AEAD payload decoding requires the payload to be over 32 bytes
			if len(bs) < 32 {
				continue
			}

			aeadCipher := account.Cipher.(*AEADCipher)
			ivLen = aeadCipher.IVSize()
			iv := bs[:ivLen]
			subkey := make([]byte, 32)
			subkey = subkey[:aeadCipher.KeyBytes]
			hkdfSHA1(account.Key, iv, subkey)
			aead = aeadCipher.AEADAuthCreator(subkey)

			var matchErr error
			switch command {
			case protocol.RequestCommandTCP:
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
