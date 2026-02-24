//go:build ipsecmb && linux && amd64 && cgo

package shadowsocks

import "testing"

func TestAES128GCMUserMatcher_MatchTCPIPsecMB(t *testing.T) {
	f := newAES128GCMMatchFixture(t, 130, 100)

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
	if ivLen != 16 {
		t.Fatalf("unexpected ivLen: %d", ivLen)
	}
}

func TestAES128GCMUserMatcher_MatchTCPIPsecMB_NotFound(t *testing.T) {
	f := newAES128GCMMatchFixture(t, 130, 100)

	tampered := append([]byte(nil), f.bs...)
	tampered[16+2] ^= 0x01
	if _, _, _, err := f.matcher.MatchTCPIPsecMB(tampered); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
}
