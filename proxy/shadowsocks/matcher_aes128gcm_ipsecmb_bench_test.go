//go:build ipsecmb

package shadowsocks

import (
	"math/rand/v2"
	"runtime"
	"testing"
)

func BenchmarkSSAEAD_AES128GCM_UserMatch_100k_Random_IPsecMB(b *testing.B) {
	const users = 100_000
	targetIdx := rand.New(rand.NewPCG(20260224, 1)).IntN(users)
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
