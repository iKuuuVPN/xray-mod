//go:build ipsecmb

package shadowsocks

import (
	"runtime"
	"testing"
)

func BenchmarkSSAEAD_AES128GCM_UserMatch_100k_Random_IPsecMB(b *testing.B) {
	const users = 100_000
	targetIdx := users - 1
	f := newAES128GCMMatchFixture(b, users, targetIdx)

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
