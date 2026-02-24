//go:build ipsecmb && linux && amd64 && cgo

package shadowsocks

import (
	"runtime"
	"testing"
)

func benchmarkSSAEAD_AESGCM_UserMatch_100k_IPsecMB(b *testing.B, cipherType CipherType) {
	const users = 100_000
	targetIdx := users - 1
	f := newAESGCMMatchFixture(b, cipherType, users, targetIdx)

	runtime.GC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		u, _, _, err := f.matcher.MatchTCPIPsecMB(f.bs)
		if err != nil {
			b.Fatal(err)
		}
		if u != f.target {
			b.Fatalf("unexpected user matched")
		}
	}
}

func BenchmarkSSAEAD_AES128GCM_UserMatch_100k_Random_IPsecMB(b *testing.B) {
	benchmarkSSAEAD_AESGCM_UserMatch_100k_IPsecMB(b, CipherType_AES_128_GCM)
}

func BenchmarkSSAEAD_AES256GCM_UserMatch_100k_Random_IPsecMB(b *testing.B) {
	benchmarkSSAEAD_AESGCM_UserMatch_100k_IPsecMB(b, CipherType_AES_256_GCM)
}
