package shadowsocks

import (
	"testing"

	"github.com/xtls/xray-core/common/protocol"
	"google.golang.org/protobuf/proto"
)

type badAccount struct{}

func (badAccount) Equals(protocol.Account) bool { return false }

func (badAccount) ToProto() proto.Message { return nil }

func TestAES128GCMUserMatcher_MatchTCP(t *testing.T) {
	f := newAES128GCMMatchFixture(t, 256, 123)

	u, aead, ivLen, err := f.matcher.MatchTCP(f.bs)
	if err != nil {
		t.Fatal(err)
	}
	if u != f.target {
		t.Fatalf("unexpected user matched")
	}
	if aead == nil {
		t.Fatalf("expected aead")
	}
	if ivLen != 16 {
		t.Fatalf("unexpected ivLen: %d", ivLen)
	}

	sizeCipherText := f.bs[16 : 16+2+16]
	var nonce [12]byte
	var plain [2]byte
	if _, err := aead.Open(plain[:0], nonce[:], sizeCipherText, nil); err != nil {
		t.Fatal(err)
	}
}

func TestAES128GCMUserMatcher_MatchTCP_NotFound(t *testing.T) {
	f := newAES128GCMMatchFixture(t, 128, 0)

	short := f.bs[:16+2+16-1]
	if _, _, _, err := f.matcher.MatchTCP(short); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}

	tampered := append([]byte(nil), f.bs...)
	tampered[16+2] ^= 0x01
	if _, _, _, err := f.matcher.MatchTCP(tampered); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}

func TestNewAES128GCMUserMatcher_ValidatesUsers(t *testing.T) {
	if _, err := NewAES128GCMUserMatcher([]*protocol.MemoryUser{{
		Account: badAccount{},
	}}); err == nil {
		t.Fatal("expected error")
	}

	if _, err := NewAES128GCMUserMatcher([]*protocol.MemoryUser{{
		Account: &MemoryAccount{
			CipherType: CipherType_AES_256_GCM,
			Key:        make([]byte, 16),
		},
	}}); err == nil {
		t.Fatal("expected error")
	}

	if _, err := NewAES128GCMUserMatcher([]*protocol.MemoryUser{{
		Account: &MemoryAccount{
			CipherType: CipherType_AES_128_GCM,
			Key:        make([]byte, 15),
		},
	}}); err == nil {
		t.Fatal("expected error")
	}
}
