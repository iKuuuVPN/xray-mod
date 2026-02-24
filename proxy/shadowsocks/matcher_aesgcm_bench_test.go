package shadowsocks

import (
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

func newAESGCMUser(tb testing.TB, cipherType CipherType, cipher *AEADCipher, idx int) *protocol.MemoryUser {
	tb.Helper()

	key := make([]byte, int(cipher.KeyBytes))
	binary.LittleEndian.PutUint64(key[:8], uint64(idx))
	binary.LittleEndian.PutUint64(key[8:16], uint64(idx)^0x9e3779b97f4a7c15)
	if cipher.KeyBytes == 32 {
		binary.LittleEndian.PutUint64(key[16:24], uint64(idx)^0xbf58476d1ce4e5b9)
		binary.LittleEndian.PutUint64(key[24:32], uint64(idx)^0x94d049bb133111eb)
	}

	return &protocol.MemoryUser{
		Account: &MemoryAccount{
			Cipher:     cipher,
			CipherType: cipherType,
			Key:        key,
		},
	}
}

type aesgcmMatchFixture struct {
	validator *Validator
	matcher   *AESGCMUserMatcher
	bs        []byte
	target    *protocol.MemoryUser
}

func newAESGCMMatchFixture(tb testing.TB, cipherType CipherType, users int, targetIdx int) *aesgcmMatchFixture {
	tb.Helper()

	keyLen, err := aeadKeyLen(cipherType)
	if err != nil {
		tb.Fatal(err)
	}

	cipher := &AEADCipher{
		KeyBytes:        keyLen,
		IVBytes:         keyLen,
		AEADAuthCreator: createAesGcm,
	}

	all := make([]*protocol.MemoryUser, 0, users)
	validator := new(Validator)
	for i := 0; i < users; i++ {
		u := newAESGCMUser(tb, cipherType, cipher, i)
		all = append(all, u)
		common.Must(validator.Add(u))
	}

	matcher, err := NewAESGCMUserMatcher(all, cipherType)
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

	return &aesgcmMatchFixture{
		validator: validator,
		matcher:   matcher,
		bs:        append([]byte(nil), cache.Bytes()...),
		target:    target,
	}
}

func benchmarkSSAEAD_AESGCM_UserMatch_100k_ValidatorGet(b *testing.B, cipherType CipherType) {
	const users = 100_000
	targetIdx := users - 1
	f := newAESGCMMatchFixture(b, cipherType, users, targetIdx)

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

func benchmarkSSAEAD_AESGCM_UserMatch_100k_ExtractedMatcher(b *testing.B, cipherType CipherType) {
	const users = 100_000
	targetIdx := users - 1
	f := newAESGCMMatchFixture(b, cipherType, users, targetIdx)

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

func BenchmarkSSAEAD_AES128GCM_UserMatch_100k_Random_ValidatorGet(b *testing.B) {
	benchmarkSSAEAD_AESGCM_UserMatch_100k_ValidatorGet(b, CipherType_AES_128_GCM)
}

func BenchmarkSSAEAD_AES128GCM_UserMatch_100k_Random_ExtractedMatcher(b *testing.B) {
	benchmarkSSAEAD_AESGCM_UserMatch_100k_ExtractedMatcher(b, CipherType_AES_128_GCM)
}

func BenchmarkSSAEAD_AES256GCM_UserMatch_100k_Random_ValidatorGet(b *testing.B) {
	benchmarkSSAEAD_AESGCM_UserMatch_100k_ValidatorGet(b, CipherType_AES_256_GCM)
}

func BenchmarkSSAEAD_AES256GCM_UserMatch_100k_Random_ExtractedMatcher(b *testing.B) {
	benchmarkSSAEAD_AESGCM_UserMatch_100k_ExtractedMatcher(b, CipherType_AES_256_GCM)
}
