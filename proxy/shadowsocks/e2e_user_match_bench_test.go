package shadowsocks

import (
	"io"
	"net"
	"runtime"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func benchmarkSSAEAD_AESGCM_E2E_UserMatch_100k(b *testing.B, cipherType CipherType, useIPSecMB bool) {
	const users = 100_000
	targetIdx := users - 1
	f := newAESGCMMatchFixture(b, cipherType, users, targetIdx)
	if useIPSecMB {
		if !ipsecmbAvailable() {
			b.Skip("ipsec-mb is not enabled in this build")
		}
		if err := f.validator.EnableIPSecMB(); err != nil {
			b.Fatal(err)
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}

			func() {
				defer c.Close()

				br := buf.BufferedReader{Reader: buf.NewReader(c)}
				req, _, err := ReadTCPSession(f.validator, &br)
				if err != nil || req == nil || req.User != f.target {
					_, _ = c.Write([]byte{0})
					return
				}

				_, _ = c.Write([]byte{1})
			}()
		}
	}()

	addr := ln.Addr().String()

	b.ReportAllocs()
	runtime.GC()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			b.Fatal(err)
		}

		if _, err := c.Write(f.bs); err != nil {
			_ = c.Close()
			b.Fatal(err)
		}

		var ack [1]byte
		if _, err := io.ReadFull(c, ack[:]); err != nil {
			_ = c.Close()
			b.Fatal(err)
		}
		_ = c.Close()

		if ack[0] != 1 {
			b.Fatal("server did not accept request")
		}
	}

	b.StopTimer()
	_ = ln.Close()
	<-serverDone
}

func BenchmarkSSAEAD_AES128GCM_E2E_UserMatch_100k_Random_Original(b *testing.B) {
	benchmarkSSAEAD_AESGCM_E2E_UserMatch_100k(b, CipherType_AES_128_GCM, false)
}

func BenchmarkSSAEAD_AES128GCM_E2E_UserMatch_100k_Random_IPsecMB(b *testing.B) {
	benchmarkSSAEAD_AESGCM_E2E_UserMatch_100k(b, CipherType_AES_128_GCM, true)
}

func BenchmarkSSAEAD_AES256GCM_E2E_UserMatch_100k_Random_Original(b *testing.B) {
	benchmarkSSAEAD_AESGCM_E2E_UserMatch_100k(b, CipherType_AES_256_GCM, false)
}

func BenchmarkSSAEAD_AES256GCM_E2E_UserMatch_100k_Random_IPsecMB(b *testing.B) {
	benchmarkSSAEAD_AESGCM_E2E_UserMatch_100k(b, CipherType_AES_256_GCM, true)
}
