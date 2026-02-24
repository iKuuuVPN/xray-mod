//go:build ipsecmb && linux && amd64 && cgo

package shadowsocks

/*
#cgo LDFLAGS: -lIPSec_MB

#include <intel-ipsec-mb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef SS_MB_MAX_BURST
#define SS_MB_MAX_BURST 64
#endif

struct ss_mb_ctx {
	IMB_MGR *mgr;
	IMB_JOB hmac_jobs[SS_MB_MAX_BURST];

	uint8_t prk[SS_MB_MAX_BURST][IMB_SHA1_DIGEST_SIZE_IN_BYTES];
	uint8_t hkdf_t1[SS_MB_MAX_BURST][IMB_SHA1_DIGEST_SIZE_IN_BYTES];
	uint8_t hkdf_t2[SS_MB_MAX_BURST][IMB_SHA1_DIGEST_SIZE_IN_BYTES];
	uint8_t hkdf_t2_in[SS_MB_MAX_BURST][IMB_SHA1_DIGEST_SIZE_IN_BYTES + 9 + 1]; // T(1) || info || 0x02
	uint8_t hkdf_key32[SS_MB_MAX_BURST][32];

	uint8_t prk_ipad_hash[SS_MB_MAX_BURST][IMB_SHA1_DIGEST_SIZE_IN_BYTES];
	uint8_t prk_opad_hash[SS_MB_MAX_BURST][IMB_SHA1_DIGEST_SIZE_IN_BYTES];
	uint8_t salt_ipad_hash[IMB_SHA1_DIGEST_SIZE_IN_BYTES];
	uint8_t salt_opad_hash[IMB_SHA1_DIGEST_SIZE_IN_BYTES];

	struct gcm_key_data *gcm_keys; // 64B aligned
	struct gcm_context_data gcm_ctx[SS_MB_MAX_BURST];
	uint8_t tags[SS_MB_MAX_BURST][IMB_MAX_TAG_LEN];
	uint8_t plain[SS_MB_MAX_BURST][16];
};

static struct ss_mb_ctx *ss_mb_ctx_new(void) {
	struct ss_mb_ctx *ctx = (struct ss_mb_ctx *) calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}

	ctx->mgr = alloc_mb_mgr(0);
	if (ctx->mgr == NULL) {
		free(ctx);
		return NULL;
	}
	init_mb_mgr_auto(ctx->mgr, NULL);

	void *aligned = NULL;
	if (posix_memalign(&aligned, 64, SS_MB_MAX_BURST * sizeof(struct gcm_key_data)) != 0) {
		free_mb_mgr(ctx->mgr);
		free(ctx);
		return NULL;
	}
	memset(aligned, 0, SS_MB_MAX_BURST * sizeof(struct gcm_key_data));
	ctx->gcm_keys = (struct gcm_key_data *) aligned;

	return ctx;
}

static void ss_mb_ctx_free(struct ss_mb_ctx *ctx) {
	if (ctx == NULL) {
		return;
	}
	if (ctx->gcm_keys != NULL) {
		free(ctx->gcm_keys);
		ctx->gcm_keys = NULL;
	}
	if (ctx->mgr != NULL) {
		free_mb_mgr(ctx->mgr);
		ctx->mgr = NULL;
	}
	free(ctx);
}

static void ss_xor_pad64(uint8_t out[64], const uint8_t in[64], const uint8_t pad) {
	for (int i = 0; i < 64; i++) {
		out[i] = in[i] ^ pad;
	}
}

static int ss_mb_match_aes128gcm(struct ss_mb_ctx *ctx,
                                 const uint8_t *keys_flat, const size_t n_keys,
                                 const uint8_t salt16[16],
                                 const uint8_t ct2[2],
                                 const uint8_t tag16[16],
                                 size_t *match_index) {
	if (ctx == NULL || ctx->mgr == NULL || ctx->gcm_keys == NULL || match_index == NULL) {
		return -1;
	}
	if (n_keys == 0) {
		return 1;
	}

	uint8_t salt_key_block[64] = {0};
	memcpy(salt_key_block, salt16, 16);

	uint8_t salt_ipad_block[64];
	uint8_t salt_opad_block[64];
	ss_xor_pad64(salt_ipad_block, salt_key_block, 0x36);
	ss_xor_pad64(salt_opad_block, salt_key_block, 0x5c);
	IMB_SHA1_ONE_BLOCK(ctx->mgr, salt_ipad_block, ctx->salt_ipad_hash);
	IMB_SHA1_ONE_BLOCK(ctx->mgr, salt_opad_block, ctx->salt_opad_hash);

	static const uint8_t info_msg1[10] = {
		's', 's', '-', 's', 'u', 'b', 'k', 'e', 'y', 0x01
	};
	static const uint8_t nonce0[12] = {0};

	for (size_t base = 0; base < n_keys; base += SS_MB_MAX_BURST) {
		size_t n = n_keys - base;
		if (n > SS_MB_MAX_BURST) {
			n = SS_MB_MAX_BURST;
		}

		// HKDF-Extract: PRK = HMAC-SHA1(salt, key)
		for (size_t i = 0; i < n; i++) {
			IMB_JOB *job = &ctx->hmac_jobs[i];
			memset(job, 0, sizeof(*job));
			job->cipher_mode = IMB_CIPHER_NULL;
			job->hash_alg = IMB_AUTH_HMAC_SHA_1;
			job->chain_order = IMB_ORDER_CIPHER_HASH;
			job->u.HMAC._hashed_auth_key_xor_ipad = ctx->salt_ipad_hash;
			job->u.HMAC._hashed_auth_key_xor_opad = ctx->salt_opad_hash;
			job->src = keys_flat + ((base + i) * 16);
			job->hash_start_src_offset_in_bytes = 0;
			job->msg_len_to_hash_in_bytes = 16;
			job->auth_tag_output = ctx->prk[i];
			job->auth_tag_output_len_in_bytes = IMB_SHA1_DIGEST_SIZE_IN_BYTES;
		}

		uint32_t completed = IMB_SUBMIT_HASH_BURST_NOCHECK(ctx->mgr, ctx->hmac_jobs,
		                                                   (uint32_t) n,
		                                                   IMB_AUTH_HMAC_SHA_1);
		if (completed != (uint32_t) n) {
			return -2;
		}

		// HKDF-Expand: T(1) = HMAC-SHA1(PRK, info || 0x01)
		for (size_t i = 0; i < n; i++) {
			uint8_t prk_key_block[64] = {0};
			memcpy(prk_key_block, ctx->prk[i], IMB_SHA1_DIGEST_SIZE_IN_BYTES);

			uint8_t prk_ipad_block[64];
			uint8_t prk_opad_block[64];
			ss_xor_pad64(prk_ipad_block, prk_key_block, 0x36);
			ss_xor_pad64(prk_opad_block, prk_key_block, 0x5c);
			IMB_SHA1_ONE_BLOCK(ctx->mgr, prk_ipad_block, ctx->prk_ipad_hash[i]);
			IMB_SHA1_ONE_BLOCK(ctx->mgr, prk_opad_block, ctx->prk_opad_hash[i]);
		}

		for (size_t i = 0; i < n; i++) {
			IMB_JOB *job = &ctx->hmac_jobs[i];
			memset(job, 0, sizeof(*job));
			job->cipher_mode = IMB_CIPHER_NULL;
			job->hash_alg = IMB_AUTH_HMAC_SHA_1;
			job->chain_order = IMB_ORDER_CIPHER_HASH;
			job->u.HMAC._hashed_auth_key_xor_ipad = ctx->prk_ipad_hash[i];
			job->u.HMAC._hashed_auth_key_xor_opad = ctx->prk_opad_hash[i];
			job->src = info_msg1;
			job->hash_start_src_offset_in_bytes = 0;
			job->msg_len_to_hash_in_bytes = sizeof(info_msg1);
			job->auth_tag_output = ctx->hkdf_t1[i];
			job->auth_tag_output_len_in_bytes = IMB_SHA1_DIGEST_SIZE_IN_BYTES;
		}

		completed = IMB_SUBMIT_HASH_BURST_NOCHECK(ctx->mgr, ctx->hmac_jobs,
		                                          (uint32_t) n,
		                                          IMB_AUTH_HMAC_SHA_1);
		if (completed != (uint32_t) n) {
			return -3;
		}

		// Match: AES-128-GCM over 2-byte ciphertext, nonce=0, AAD=nil.
		for (size_t i = 0; i < n; i++) {
			IMB_AES128_GCM_PRE(ctx->mgr, ctx->hkdf_t1[i], &ctx->gcm_keys[i]);

			memset(&ctx->gcm_ctx[i], 0, sizeof(struct gcm_context_data));
			IMB_AES128_GCM_DEC(ctx->mgr, &ctx->gcm_keys[i], &ctx->gcm_ctx[i],
			                   ctx->plain[i], ct2, 2,
			                   nonce0, NULL, 0,
			                   ctx->tags[i], 16);

			if (memcmp(ctx->tags[i], tag16, 16) == 0) {
				*match_index = base + i;
				return 0;
			}
		}
	}

	return 1;
}

static int ss_mb_match_aes256gcm(struct ss_mb_ctx *ctx,
                                 const uint8_t *keys_flat, const size_t n_keys,
                                 const uint8_t salt32[32],
                                 const uint8_t ct2[2],
                                 const uint8_t tag16[16],
                                 size_t *match_index) {
	if (ctx == NULL || ctx->mgr == NULL || ctx->gcm_keys == NULL || match_index == NULL) {
		return -1;
	}
	if (n_keys == 0) {
		return 1;
	}

	uint8_t salt_key_block[64] = {0};
	memcpy(salt_key_block, salt32, 32);

	uint8_t salt_ipad_block[64];
	uint8_t salt_opad_block[64];
	ss_xor_pad64(salt_ipad_block, salt_key_block, 0x36);
	ss_xor_pad64(salt_opad_block, salt_key_block, 0x5c);
	IMB_SHA1_ONE_BLOCK(ctx->mgr, salt_ipad_block, ctx->salt_ipad_hash);
	IMB_SHA1_ONE_BLOCK(ctx->mgr, salt_opad_block, ctx->salt_opad_hash);

	static const uint8_t info[9] = {
		's', 's', '-', 's', 'u', 'b', 'k', 'e', 'y'
	};
	static const uint8_t info_msg1[10] = {
		's', 's', '-', 's', 'u', 'b', 'k', 'e', 'y', 0x01
	};
	static const uint8_t nonce0[12] = {0};

	for (size_t base = 0; base < n_keys; base += SS_MB_MAX_BURST) {
		size_t n = n_keys - base;
		if (n > SS_MB_MAX_BURST) {
			n = SS_MB_MAX_BURST;
		}

		// HKDF-Extract: PRK = HMAC-SHA1(salt, key)
		for (size_t i = 0; i < n; i++) {
			IMB_JOB *job = &ctx->hmac_jobs[i];
			memset(job, 0, sizeof(*job));
			job->cipher_mode = IMB_CIPHER_NULL;
			job->hash_alg = IMB_AUTH_HMAC_SHA_1;
			job->chain_order = IMB_ORDER_CIPHER_HASH;
			job->u.HMAC._hashed_auth_key_xor_ipad = ctx->salt_ipad_hash;
			job->u.HMAC._hashed_auth_key_xor_opad = ctx->salt_opad_hash;
			job->src = keys_flat + ((base + i) * 32);
			job->hash_start_src_offset_in_bytes = 0;
			job->msg_len_to_hash_in_bytes = 32;
			job->auth_tag_output = ctx->prk[i];
			job->auth_tag_output_len_in_bytes = IMB_SHA1_DIGEST_SIZE_IN_BYTES;
		}

		uint32_t completed = IMB_SUBMIT_HASH_BURST_NOCHECK(ctx->mgr, ctx->hmac_jobs,
		                                                   (uint32_t) n,
		                                                   IMB_AUTH_HMAC_SHA_1);
		if (completed != (uint32_t) n) {
			return -2;
		}

		// HKDF-Expand: T(1) = HMAC-SHA1(PRK, info || 0x01)
		for (size_t i = 0; i < n; i++) {
			uint8_t prk_key_block[64] = {0};
			memcpy(prk_key_block, ctx->prk[i], IMB_SHA1_DIGEST_SIZE_IN_BYTES);

			uint8_t prk_ipad_block[64];
			uint8_t prk_opad_block[64];
			ss_xor_pad64(prk_ipad_block, prk_key_block, 0x36);
			ss_xor_pad64(prk_opad_block, prk_key_block, 0x5c);
			IMB_SHA1_ONE_BLOCK(ctx->mgr, prk_ipad_block, ctx->prk_ipad_hash[i]);
			IMB_SHA1_ONE_BLOCK(ctx->mgr, prk_opad_block, ctx->prk_opad_hash[i]);
		}

		for (size_t i = 0; i < n; i++) {
			IMB_JOB *job = &ctx->hmac_jobs[i];
			memset(job, 0, sizeof(*job));
			job->cipher_mode = IMB_CIPHER_NULL;
			job->hash_alg = IMB_AUTH_HMAC_SHA_1;
			job->chain_order = IMB_ORDER_CIPHER_HASH;
			job->u.HMAC._hashed_auth_key_xor_ipad = ctx->prk_ipad_hash[i];
			job->u.HMAC._hashed_auth_key_xor_opad = ctx->prk_opad_hash[i];
			job->src = info_msg1;
			job->hash_start_src_offset_in_bytes = 0;
			job->msg_len_to_hash_in_bytes = sizeof(info_msg1);
			job->auth_tag_output = ctx->hkdf_t1[i];
			job->auth_tag_output_len_in_bytes = IMB_SHA1_DIGEST_SIZE_IN_BYTES;
		}

		completed = IMB_SUBMIT_HASH_BURST_NOCHECK(ctx->mgr, ctx->hmac_jobs,
		                                          (uint32_t) n,
		                                          IMB_AUTH_HMAC_SHA_1);
		if (completed != (uint32_t) n) {
			return -3;
		}

		// HKDF-Expand: T(2) = HMAC-SHA1(PRK, T(1) || info || 0x02)
		for (size_t i = 0; i < n; i++) {
			memcpy(ctx->hkdf_t2_in[i], ctx->hkdf_t1[i], IMB_SHA1_DIGEST_SIZE_IN_BYTES);
			memcpy(ctx->hkdf_t2_in[i] + IMB_SHA1_DIGEST_SIZE_IN_BYTES, info, sizeof(info));
			ctx->hkdf_t2_in[i][IMB_SHA1_DIGEST_SIZE_IN_BYTES + sizeof(info)] = 0x02;
		}

		for (size_t i = 0; i < n; i++) {
			IMB_JOB *job = &ctx->hmac_jobs[i];
			memset(job, 0, sizeof(*job));
			job->cipher_mode = IMB_CIPHER_NULL;
			job->hash_alg = IMB_AUTH_HMAC_SHA_1;
			job->chain_order = IMB_ORDER_CIPHER_HASH;
			job->u.HMAC._hashed_auth_key_xor_ipad = ctx->prk_ipad_hash[i];
			job->u.HMAC._hashed_auth_key_xor_opad = ctx->prk_opad_hash[i];
			job->src = ctx->hkdf_t2_in[i];
			job->hash_start_src_offset_in_bytes = 0;
			job->msg_len_to_hash_in_bytes = IMB_SHA1_DIGEST_SIZE_IN_BYTES + sizeof(info) + 1;
			job->auth_tag_output = ctx->hkdf_t2[i];
			job->auth_tag_output_len_in_bytes = IMB_SHA1_DIGEST_SIZE_IN_BYTES;
		}

		completed = IMB_SUBMIT_HASH_BURST_NOCHECK(ctx->mgr, ctx->hmac_jobs,
		                                          (uint32_t) n,
		                                          IMB_AUTH_HMAC_SHA_1);
		if (completed != (uint32_t) n) {
			return -4;
		}

		// Match: AES-256-GCM over 2-byte ciphertext, nonce=0, AAD=nil.
		for (size_t i = 0; i < n; i++) {
			memcpy(ctx->hkdf_key32[i], ctx->hkdf_t1[i], IMB_SHA1_DIGEST_SIZE_IN_BYTES);
			memcpy(ctx->hkdf_key32[i] + IMB_SHA1_DIGEST_SIZE_IN_BYTES, ctx->hkdf_t2[i], 32 - IMB_SHA1_DIGEST_SIZE_IN_BYTES);

			IMB_AES256_GCM_PRE(ctx->mgr, ctx->hkdf_key32[i], &ctx->gcm_keys[i]);

			memset(&ctx->gcm_ctx[i], 0, sizeof(struct gcm_context_data));
			IMB_AES256_GCM_DEC(ctx->mgr, &ctx->gcm_keys[i], &ctx->gcm_ctx[i],
			                   ctx->plain[i], ct2, 2,
			                   nonce0, NULL, 0,
			                   ctx->tags[i], 16);

			if (memcmp(ctx->tags[i], tag16, 16) == 0) {
				*match_index = base + i;
				return 0;
			}
		}
	}

	return 1;
}

*/
import "C"

import (
	"crypto/cipher"
	"runtime"
	"sync"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
)

type ssIPSecMBCtx struct {
	ptr *C.struct_ss_mb_ctx
}

var ssIPSecMBCtxPool = sync.Pool{
	New: func() any {
		return &ssIPSecMBCtx{ptr: C.ss_mb_ctx_new()}
	},
}

func (m *AESGCMUserMatcher) MatchTCPIPsecMB(bs []byte) (u *protocol.MemoryUser, aead cipher.AEAD, ivLen int32, err error) {
	if len(m.users) == 0 {
		return nil, nil, 0, ErrNotFound
	}
	if len(bs) < int(m.keyLen)+2+16 {
		return nil, nil, 0, ErrNotFound
	}

	salt := bs[:m.keyLen]
	ct2 := bs[m.keyLen : m.keyLen+2]
	tag := bs[m.keyLen+2 : m.keyLen+2+16]

	ctx := ssIPSecMBCtxPool.Get().(*ssIPSecMBCtx)
	defer ssIPSecMBCtxPool.Put(ctx)

	if ctx.ptr == nil {
		return nil, nil, 0, errors.New("ipsec-mb context unavailable")
	}

	var matchIdx C.size_t
	var rc C.int
	switch m.keyLen {
	case 16:
		rc = C.ss_mb_match_aes128gcm(
			ctx.ptr,
			(*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(m.keysFlat))),
			C.size_t(len(m.users)),
			(*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(salt))),
			(*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(ct2))),
			(*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(tag))),
			(*C.size_t)(unsafe.Pointer(&matchIdx)),
		)
	case 32:
		rc = C.ss_mb_match_aes256gcm(
			ctx.ptr,
			(*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(m.keysFlat))),
			C.size_t(len(m.users)),
			(*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(salt))),
			(*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(ct2))),
			(*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(tag))),
			(*C.size_t)(unsafe.Pointer(&matchIdx)),
		)
	default:
		return nil, nil, 0, errors.New("unexpected key length: ", m.keyLen)
	}
	runtime.KeepAlive(m.keysFlat)
	runtime.KeepAlive(bs)

	switch rc {
	case 0:
		idx := int(matchIdx)
		if idx < 0 || idx >= len(m.users) {
			return nil, nil, 0, errors.New("ipsec-mb returned invalid match index: ", idx)
		}
		key := m.keysFlat[idx*int(m.keyLen) : idx*int(m.keyLen)+int(m.keyLen)]
		var subkey [32]byte
		hkdfSHA1(key, salt, subkey[:m.keyLen])
		aead = createAesGcm(subkey[:m.keyLen])
		return m.users[idx], aead, m.keyLen, nil
	case 1:
		return nil, nil, 0, ErrNotFound
	default:
		return nil, nil, 0, errors.New("ipsec-mb match failed with code: ", int(rc))
	}
}
