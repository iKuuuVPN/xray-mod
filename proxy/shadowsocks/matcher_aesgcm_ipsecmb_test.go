//go:build ipsecmb && linux && amd64 && cgo

package shadowsocks

import "testing"

func TestAESGCMUserMatcher_MatchTCPIPsecMB(t *testing.T) {
	for _, tt := range []struct {
		name      string
		cipher    CipherType
		wantIVLen int32
	}{
		{name: "AES128GCM", cipher: CipherType_AES_128_GCM, wantIVLen: 16},
		{name: "AES256GCM", cipher: CipherType_AES_256_GCM, wantIVLen: 32},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newAESGCMMatchFixture(t, tt.cipher, 130, 100)

			u, aead, ivLen, err := f.matcher.MatchTCPIPsecMB(f.bs)
			if err != nil {
				t.Fatal(err)
			}
			if u != f.target {
				t.Fatalf("unexpected user matched")
			}
			if aead == nil {
				t.Fatalf("expected aead")
			}
			if ivLen != tt.wantIVLen {
				t.Fatalf("unexpected ivLen: %d", ivLen)
			}
		})
	}
}

func TestAESGCMUserMatcher_MatchTCPIPsecMB_NotFound(t *testing.T) {
	for _, tt := range []struct {
		name   string
		cipher CipherType
	}{
		{name: "AES128GCM", cipher: CipherType_AES_128_GCM},
		{name: "AES256GCM", cipher: CipherType_AES_256_GCM},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newAESGCMMatchFixture(t, tt.cipher, 130, 100)

			tampered := append([]byte(nil), f.bs...)
			ivLenInt := int(f.matcher.keyLen)
			tampered[ivLenInt+2] ^= 0x01
			if _, _, _, err := f.matcher.MatchTCPIPsecMB(tampered); err != ErrNotFound {
				t.Fatalf("expected ErrNotFound, got: %v", err)
			}
		})
	}
}
