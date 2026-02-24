package shadowsocks

import (
	"encoding/binary"
	"math/rand/v2"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

func newAES128GCMUser(tb testing.TB, cipher *AEADCipher, idx int) *protocol.MemoryUser {
	tb.Helper()

	key := make([]byte, 16)
	binary.LittleEndian.PutUint64(key[:8], uint64(idx))
	binary.LittleEndian.PutUint64(key[8:], uint64(idx)^0x9e3779b97f4a7c15)

	return &protocol.MemoryUser{
		Account: &MemoryAccount{
			Cipher:     cipher,
			CipherType: CipherType_AES_128_GCM,
			Key:        key,
		},
	}
}

type aes128gcmMatchFixture struct {
	validator *Validator
	matcher   *AES128GCMUserMatcher
	bs        []byte
	target    *protocol.MemoryUser
}

func newAES128GCMMatchFixture(tb testing.TB, users int, targetIdx int) *aes128gcmMatchFixture {
	tb.Helper()

	cipher := &AEADCipher{
		KeyBytes:        16,
		IVBytes:         16,
		AEADAuthCreator: createAesGcm,
	}

	all := make([]*protocol.MemoryUser, 0, users)
	validator := new(Validator)
	for i := 0; i < users; i++ {
		u := newAES128GCMUser(tb, cipher, i)
		all = append(all, u)
		common.Must(validator.Add(u))
	}

	matcher, err := NewAES128GCMUserMatcher(all)
	if err != nil {
		tb.Fatal(err)
	}

	target := all[targetIdx]
	req := &protocol.RequestHeader{
		Version: Version,
		Command: protocol.RequestCommandTCP,
		Address: net.DomainAddress("example.com"),
		Port:    1234,
		User:    target,
	}

	cache := buf.New()
	defer cache.Release()

	_, err = WriteTCPRequest(req, cache)
	common.Must(err)

	return &aes128gcmMatchFixture{
		validator: validator,
		matcher:   matcher,
		bs:        append([]byte(nil), cache.Bytes()...),
		target:    target,
	}
}

func BenchmarkSSAEAD_AES128GCM_UserMatch_100k_Random_ValidatorGet(b *testing.B) {
	const users = 100_000
	targetIdx := rand.New(rand.NewPCG(20260224, 1)).IntN(users)
	f := newAES128GCMMatchFixture(b, users, targetIdx)

	runtime.GC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		u, _, _, _, err := f.validator.Get(f.bs, protocol.RequestCommandTCP)
		if err != nil {
			b.Fatal(err)
		}
		if u != f.target {
			b.Fatalf("unexpected user matched")
		}
	}
}

func BenchmarkSSAEAD_AES128GCM_UserMatch_100k_Random_ExtractedMatcher(b *testing.B) {
	const users = 100_000
	targetIdx := rand.New(rand.NewPCG(20260224, 1)).IntN(users)
	f := newAES128GCMMatchFixture(b, users, targetIdx)

	runtime.GC()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		u, _, _, err := f.matcher.MatchTCP(f.bs)
		if err != nil {
			b.Fatal(err)
		}
		if u != f.target {
			b.Fatalf("unexpected user matched")
		}
	}
}
