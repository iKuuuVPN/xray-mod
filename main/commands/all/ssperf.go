package all

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand/v2"
	stdnet "net"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xcrypto "github.com/xtls/xray-core/common/crypto"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/main/commands/base"
	"github.com/xtls/xray-core/proxy/shadowsocks"
)

var cmdSSPerf = &base.Command{
	UsageLine: `{{.Exec}} ssperf [-users 100000] [-iters 3] [-cipher aes-128-gcm|aes-256-gcm] [-e2e] [-e2e-iters 3] [-mode both|original|ipsecmb] [-target last|random] [-target-idx N] [-seed N]`,
	Short:     `Benchmark Shadowsocks AEAD AES-GCM user matching`,
	Long: `
Benchmark Shadowsocks AEAD AES-GCM user matching (aes-128-gcm / aes-256-gcm).

Examples:

Worst-case 100k user match (target = last user):
  {{.Exec}} ssperf

Worst-case 100k user match with aes-256-gcm:
  {{.Exec}} ssperf -cipher aes-256-gcm

Random target (reproducible):
  {{.Exec}} ssperf -target random -seed 1

Only run original matcher (no ipsec-mb):
  {{.Exec}} ssperf -mode original

Notes:
  - ipsec-mb mode requires building with: -tags ipsecmb (linux/amd64/cgo)
`,
}

func init() {
	cmdSSPerf.Run = executeSSPerf // break init loop
}

var (
	ssperfUsers     = cmdSSPerf.Flag.Int("users", 100_000, "")
	ssperfIters     = cmdSSPerf.Flag.Int("iters", 3, "")
	ssperfCipher    = cmdSSPerf.Flag.String("cipher", "aes-128-gcm", "")
	ssperfMode      = cmdSSPerf.Flag.String("mode", "both", "")
	ssperfTarget    = cmdSSPerf.Flag.String("target", "last", "")
	ssperfTargetIdx = cmdSSPerf.Flag.Int("target-idx", -1, "")
	ssperfSeed      = cmdSSPerf.Flag.Uint64("seed", 1, "")
	ssperfE2E       = cmdSSPerf.Flag.Bool("e2e", true, "")
	ssperfE2EIters  = cmdSSPerf.Flag.Int("e2e-iters", 3, "")
)

type ssAEADFixture struct {
	validator *shadowsocks.Validator
	bs        []byte
	target    *protocol.MemoryUser
}

type ssE2EServer struct {
	ln   stdnet.Listener
	addr string
	done chan struct{}

	validator *shadowsocks.Validator
	target    *protocol.MemoryUser
}

func parseSSPerfCipher(s string) (shadowsocks.CipherType, int32, error) {
	switch strings.ToLower(s) {
	case "aes-128-gcm", "aead_aes_128_gcm", "aes128gcm":
		return shadowsocks.CipherType_AES_128_GCM, 16, nil
	case "aes-256-gcm", "aead_aes_256_gcm", "aes256gcm":
		return shadowsocks.CipherType_AES_256_GCM, 32, nil
	default:
		return 0, 0, fmt.Errorf("unsupported cipher: %q (use aes-128-gcm|aes-256-gcm)", s)
	}
}

func startSSE2EServer(validator *shadowsocks.Validator, target *protocol.MemoryUser) (*ssE2EServer, error) {
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}

	s := &ssE2EServer{
		ln:        ln,
		addr:      ln.Addr().String(),
		done:      make(chan struct{}),
		validator: validator,
		target:    target,
	}

	go func() {
		defer close(s.done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}

			func() {
				defer c.Close()

				br := buf.BufferedReader{Reader: buf.NewReader(c)}
				req, _, err := shadowsocks.ReadTCPSession(validator, &br)
				if err != nil || req == nil || req.User != target {
					_, _ = c.Write([]byte{0})
					return
				}
				_, _ = c.Write([]byte{1})
			}()
		}
	}()

	return s, nil
}

func (s *ssE2EServer) Close() {
	_ = s.ln.Close()
	<-s.done
}

func (s *ssE2EServer) OneConn(bs []byte) error {
	c, err := stdnet.Dial("tcp", s.addr)
	if err != nil {
		return err
	}
	defer c.Close()

	if _, err := c.Write(bs); err != nil {
		return err
	}

	var ack [1]byte
	if _, err := io.ReadFull(c, ack[:]); err != nil {
		return err
	}
	if ack[0] != 1 {
		return fmt.Errorf("server did not accept request")
	}
	return nil
}

func newSSAEADFixture(users int, targetIdx int, cipherType shadowsocks.CipherType, keyLen int32) (*ssAEADFixture, error) {
	if users <= 0 {
		return nil, fmt.Errorf("users must be > 0")
	}
	if targetIdx < 0 || targetIdx >= users {
		return nil, fmt.Errorf("target index out of range: %d", targetIdx)
	}

	cipher := &shadowsocks.AEADCipher{
		KeyBytes:        keyLen,
		IVBytes:         keyLen,
		AEADAuthCreator: xcrypto.NewAesGcm,
	}

	all := make([]*protocol.MemoryUser, 0, users)
	validator := new(shadowsocks.Validator)
	for i := 0; i < users; i++ {
		key := make([]byte, int(keyLen))
		binary.LittleEndian.PutUint64(key[:8], uint64(i))
		binary.LittleEndian.PutUint64(key[8:16], uint64(i)^0x9e3779b97f4a7c15)
		if keyLen == 32 {
			binary.LittleEndian.PutUint64(key[16:24], uint64(i)^0xbf58476d1ce4e5b9)
			binary.LittleEndian.PutUint64(key[24:32], uint64(i)^0x94d049bb133111eb)
		}

		u := &protocol.MemoryUser{
			Account: &shadowsocks.MemoryAccount{
				Cipher:     cipher,
				CipherType: cipherType,
				Key:        key,
			},
		}
		all = append(all, u)
		if err := validator.Add(u); err != nil {
			return nil, err
		}
	}

	target := all[targetIdx]
	req := &protocol.RequestHeader{
		Version: shadowsocks.Version,
		Command: protocol.RequestCommandTCP,
		Address: xnet.DomainAddress("example.com"),
		Port:    1234,
		User:    target,
	}

	var b bytes.Buffer
	if _, err := shadowsocks.WriteTCPRequest(req, &b); err != nil {
		return nil, err
	}

	return &ssAEADFixture{
		validator: validator,
		bs:        append([]byte(nil), b.Bytes()...),
		target:    target,
	}, nil
}

type perfStats struct {
	Durations []time.Duration
	Allocs    uint64
	Bytes     uint64
}

func measure(iters int, fn func() error) (perfStats, error) {
	if iters <= 0 {
		iters = 1
	}

	// Warm up (also ensures any one-time init happens outside the measured loop).
	if err := fn(); err != nil {
		return perfStats{}, err
	}

	runtime.GC()
	var msStart, msEnd runtime.MemStats
	runtime.ReadMemStats(&msStart)

	durations := make([]time.Duration, 0, iters)
	for i := 0; i < iters; i++ {
		start := time.Now()
		if err := fn(); err != nil {
			return perfStats{}, err
		}
		durations = append(durations, time.Since(start))
	}

	runtime.ReadMemStats(&msEnd)
	return perfStats{
		Durations: durations,
		Allocs:    msEnd.Mallocs - msStart.Mallocs,
		Bytes:     msEnd.TotalAlloc - msStart.TotalAlloc,
	}, nil
}

func median(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), durations...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}

func mean(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	var sum time.Duration
	for _, d := range durations {
		sum += d
	}
	return sum / time.Duration(len(durations))
}

func report(label string, iters int, s perfStats) {
	med := median(s.Durations)
	avg := mean(s.Durations)
	allocsPerOp := uint64(0)
	bytesPerOp := uint64(0)
	if iters > 0 {
		allocsPerOp = s.Allocs / uint64(iters)
		bytesPerOp = s.Bytes / uint64(iters)
	}
	fmt.Printf("%s: median=%s mean=%s allocs/op=%d B/op=%d\n", label, med, avg, allocsPerOp, bytesPerOp)
}

func executeSSPerf(cmd *base.Command, args []string) {
	if len(args) != 0 {
		cmd.Usage()
		return
	}
	if *ssperfUsers <= 0 {
		base.Fatalf("users must be > 0")
	}

	cipherType, keyLen, err := parseSSPerfCipher(*ssperfCipher)
	if err != nil {
		base.Fatalf("%v", err)
	}

	targetIdx := *ssperfTargetIdx
	if targetIdx < 0 {
		switch *ssperfTarget {
		case "last":
			targetIdx = *ssperfUsers - 1
		case "random":
			targetIdx = rand.New(rand.NewPCG(*ssperfSeed, 1)).IntN(*ssperfUsers)
		default:
			base.Fatalf("unsupported target: %q (use last|random or -target-idx)", *ssperfTarget)
		}
	}

	fmt.Printf("ssperf: users=%d targetIdx=%d iters=%d cipher=%s e2e=%v e2eIters=%d mode=%s\n",
		*ssperfUsers, targetIdx, *ssperfIters, *ssperfCipher, *ssperfE2E, *ssperfE2EIters, *ssperfMode)

	setupStart := time.Now()
	f, err := newSSAEADFixture(*ssperfUsers, targetIdx, cipherType, keyLen)
	if err != nil {
		base.Fatalf("setup failed: %v", err)
	}
	fmt.Printf("setup: %s\n", time.Since(setupStart))

	runMatch := func() error {
		u, _, _, _, err := f.validator.Get(f.bs, protocol.RequestCommandTCP)
		if err != nil {
			return err
		}
		if u != f.target {
			return fmt.Errorf("unexpected user matched")
		}
		return nil
	}

	runOneMode := func(name string, enableIPSecMB bool) {
		if enableIPSecMB {
			if err := f.validator.EnableIPSecMB(); err != nil {
				fmt.Printf("%s: skip (EnableIPSecMB failed: %v)\n", name, err)
				return
			}
		}

		matchStats, err := measure(*ssperfIters, runMatch)
		if err != nil {
			base.Fatalf("%s match failed: %v", name, err)
		}
		report(name+" match", *ssperfIters, matchStats)

		if *ssperfE2E {
			if *ssperfE2EIters <= 0 {
				base.Fatalf("e2e-iters must be > 0")
			}

			srv, err := startSSE2EServer(f.validator, f.target)
			if err != nil {
				base.Fatalf("%s e2e setup failed: %v", name, err)
			}
			defer srv.Close()

			e2eStats, err := measure(*ssperfE2EIters, func() error { return srv.OneConn(f.bs) })
			if err != nil {
				base.Fatalf("%s e2e failed: %v", name, err)
			}
			report(name+" e2e", *ssperfE2EIters, e2eStats)
		}
	}

	switch *ssperfMode {
	case "original":
		runOneMode("original", false)
	case "ipsecmb":
		runOneMode("ipsecmb", true)
	case "both":
		runOneMode("original", false)
		runOneMode("ipsecmb", true)
	default:
		base.Fatalf("unsupported mode: %q (use both|original|ipsecmb)", *ssperfMode)
	}
}
