/* hbs.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfPKCS11.
 *
 * wolfPKCS11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPKCS11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Hash-based signature schemes: LMS/HSS (RFC 8554) and XMSS/XMSS^MT
 * (RFC 8391), plus the scheme-neutral framework for stateful private keys.
 *
 * The durable state file itself is storage, so it lives with the rest of the
 * store code in internal.c (wp11_Stateful_StateFile_Open / _Remove); this file
 * owns what goes into it - the AAD-bound header, the AES-GCM sealing, the
 * signature counter and the per-scheme thin wrappers.
 */

#include "wp11_types.h"
#include "hbs.h"

#ifdef WOLFPKCS11_STATEFUL_SIG_PRIVATE
/* AES-GCM encrypt with caller-supplied AAD. The tag is appended to the
 * ciphertext (out[len .. len+AES_BLOCK_SIZE-1]). Used for the state files so
 * the file header (magic, version, parameters, sig count) is bound to the
 * ciphertext via authenticated additional data; any tampering with those
 * bytes is detected at decrypt time. */
static int wp11_EncryptDataAAD(byte* out, const byte* data, int len,
    const byte* key, int keySz, const byte* iv, int ivSz,
    const byte* aad, int aadSz, int devId)
{
    Aes aes;
    int ret;

    ret = wc_AesInit(&aes, NULL, devId);
    if (ret == 0)
        ret = wc_AesGcmSetKey(&aes, key, keySz);
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(&aes, out, data, len, iv, ivSz, out + len,
            AES_BLOCK_SIZE, aad, aadSz);
    }
    wc_AesFree(&aes);

    return ret;
}

static int wp11_DecryptDataAAD(byte* out, const byte* data, int len,
    const byte* key, int keySz, const byte* iv, int ivSz,
    const byte* aad, int aadSz, int devId)
{
    Aes aes;
    int ret;

    ret = wc_AesInit(&aes, NULL, devId);
    if (ret == 0)
        ret = wc_AesGcmSetKey(&aes, key, keySz);
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&aes, out, data, len, iv, ivSz, data + len,
            AES_BLOCK_SIZE, aad, aadSz);
    }
    wc_AesFree(&aes);

    return ret;
}

/* ===========================================================================
 * Stateful hash-based signature framework
 * ===========================================================================
 *
 * Shared infrastructure for stateful hash-based signature schemes. The first
 * concrete user is LMS/HSS (RFC 8554, this file's WOLFPKCS11_LMS_PRIVATE
 * block below). Future schemes (XMSS, XMSS^MT - RFC 8391) plug into the same
 * framework via thin wrappers.
 *
 * Contract every stateful-sig scheme MUST honour:
 *
 *   1. Token-resident only. Session-only stateful keys are unsafe (a process
 *      crash between sign and cleanup can release a signature whose OTS
 *      index was never persisted). Reject CKA_TOKEN=FALSE in C_GenerateKeyPair
 *      with CKR_TEMPLATE_INCONSISTENT.
 *
 *   2. State file keyed by a per-key 64-bit nonce, NOT by the object's
 *      position in the token list. The nonce is generated at keygen time
 *      and stored in the shell file's last 8 bytes. WP11_Object holds a
 *      copy in `statefulStateId`. Token-list reordering (Add/Remove,
 *      Slot_Store) must NEVER move or delete the state file.
 *
 *   3. State persistence is synchronous and durable. The wolfSSL write
 *      callback writes the encrypted state file with fsync + atomic rename
 *      + parent-directory fsync (unless WOLFPKCS11_STATEFUL_RELAX_FSYNC=1)
 *      BEFORE returning success - so wolfSSL never releases a signature
 *      whose state advance has not reached stable storage.
 *
 *   4. State file uses AES-GCM (slot-key) with the AAD-bound header below.
 *      Tampering with parameters or the persisted sigCount fails decrypt.
 *
 *   5. SigCount tracked in the wp11 layer (`statefulSigCount`), persisted
 *      inside the AAD-bound header, and used to compute KEYS_REMAINING -
 *      no reads from wolfSSL key internals (priv_raw layout is not public
 *      API and varies between backends).
 *
 *   6. Poison-on-failure. Any state-write failure or sign error clears
 *      WP11_FLAG_STATEFUL_STATE_VALID; subsequent signs return
 *      CKR_DEVICE_ERROR until the object is reloaded from disk
 *      (wolfSSL Reload restores in-memory state from the durable file).
 *
 *   7. Locking: all post-keygen state-mutating paths run under the token
 *      lock (priv->lock points at &token->lock for token-resident keys).
 *      EXCEPTION: during the keygen function itself, priv is thread-local
 *      (no other thread has the handle yet, and priv->lock has not been
 *      assigned by WP11_Session_AddObject), so the write callback fires
 *      unlocked. This is safe only because no concurrent reader can find
 *      priv before keygen returns.
 *
 * On-disk layouts:
 *
 *   Shell file (per scheme; non-secret metadata):
 *     [u32 magic][u32 version][scheme-specific params + pub][u64 stateId]
 *     The trailer (stateId) is always the last 8 bytes - that's how
 *     wp11_Stateful_PeekStateIdFromShell finds it without parsing.
 *
 *   State file (AES-GCM, AAD-bound):
 *     AAD: [u32 magic][u32 version][scheme params (P bytes)][u64 sigCount]
 *     [u32 ivLen][iv (12 bytes)]
 *     [u32 ctLen][ciphertext (privSz + 16-byte GCM tag)]
 */

/* Big-endian byte helpers for encoding/decoding the AAD-bound state header
 * and the shell trailer (compiled in sign builds only - the whole framework
 * is gated by WOLFPKCS11_STATEFUL_SIG_PRIVATE above). */
static word32 wp11_Stateful_ReadU32(const byte* p)
{
    return ((word32)p[0] << 24) | ((word32)p[1] << 16)
         | ((word32)p[2] << 8)  |  (word32)p[3];
}

static word64 wp11_Stateful_ReadU64(const byte* p)
{
    return ((word64)p[0] << 56) | ((word64)p[1] << 48)
         | ((word64)p[2] << 40) | ((word64)p[3] << 32)
         | ((word64)p[4] << 24) | ((word64)p[5] << 16)
         | ((word64)p[6] << 8)  |  (word64)p[7];
}

static void wp11_Stateful_WriteU32(byte* p, word32 v)
{
    p[0] = (byte)(v >> 24);
    p[1] = (byte)(v >> 16);
    p[2] = (byte)(v >> 8);
    p[3] = (byte)v;
}

static void wp11_Stateful_WriteU64(byte* p, word64 v)
{
    p[0] = (byte)(v >> 56);
    p[1] = (byte)(v >> 48);
    p[2] = (byte)(v >> 40);
    p[3] = (byte)(v >> 32);
    p[4] = (byte)(v >> 24);
    p[5] = (byte)(v >> 16);
    p[6] = (byte)(v >> 8);
    p[7] = (byte)v;
}

/* IV length for the AES-GCM-encrypted state file. The full 96-bit GCM
 * standard IV; same for every scheme. */
#define WP11_STATEFUL_IV_LEN          12

/* Cached env-var read once at first use: when 1, the state-write callback
 * skips fsync() (file and directory). DANGEROUS: documented as non-production
 * only. Default is to always fsync. The variable applies to ALL stateful
 * hash-based signature schemes (LMS/HSS today; XMSS in the future) - there
 * is no per-scheme knob, since the durability requirement is identical. */
static int wp11_StatefulRelaxFsync = -1;

static int wp11_StatefulShouldFsync(void)
{
    if (wp11_StatefulRelaxFsync < 0) {
#ifndef WOLFPKCS11_NO_ENV
        const char* v = XGETENV("WOLFPKCS11_STATEFUL_RELAX_FSYNC");
        wp11_StatefulRelaxFsync = (v != NULL && v[0] == '1' && v[1] == '\0') ? 1 : 0;
#else
        wp11_StatefulRelaxFsync = 0;
#endif
        if (wp11_StatefulRelaxFsync) {
            /* Single, prominent stderr line - the README documents this is
             * non-production. Operators who reach this path must see it. */
            fprintf(stderr,
                "wolfPKCS11: WARNING: WOLFPKCS11_STATEFUL_RELAX_FSYNC=1 is "
                "set. Stateful hash-signature state writes will skip fsync; "
                "a power loss can roll back the leaf-index advance and cause "
                "OTS-key REUSE. Do NOT use this setting in production.\n");
        }
    }
    return wp11_StatefulRelaxFsync ? 0 : 1;
}

/* Sanity caps for inputs to the generic state-blob helpers. The wolfSSL
 * state buffer for any practical scheme is well below 1 MiB; the scheme
 * parameter region is small (HSS = 12 bytes, XMSS = 4-12 bytes). Reject
 * absurd inputs up front so the size-arithmetic below cannot overflow. */
#define WP11_STATEFUL_PRIV_MAX        (1U << 20)   /* 1 MiB */
#define WP11_STATEFUL_PARAMS_MAX      256U

/* Persist the encrypted state file durably. Caller passes the scheme's
 * (schemeFilePrefix, magic, version) and a packed scheme-params buffer
 * that is bound into the GCM AAD. On a successful return the state file
 * at (slot_id, statefulStateId) is fsync'd and renamed atomically.
 *
 * AAD-bound layout (caught by AES-GCM tag):
 *   [u32 magic][u32 version][u32 schemeParamLen][schemeParamBytes]
 *   [u64 sigCount]
 * Including schemeParamLen in the AAD diagnoses thin-wrapper version skew
 * cleanly (a length mismatch surfaces as a header-mismatch BAD_FUNC_ARG
 * before decrypt rather than as opaque AES-GCM tag failure). */
static int wp11_Stateful_WriteStateBlob(WP11_Object* o,
    const char* schemeFilePrefix, word32 magic, word32 version,
    const byte* schemeParamBytes, word32 schemeParamLen,
    const byte* priv, word32 privSz)
{
    int ret;
    void* storage = NULL;
    byte iv[WP11_STATEFUL_IV_LEN];
    byte* hdr = NULL;
    word32 hdrLen;
    byte* ct = NULL;
    word32 ctLen;
    int tokenId;

    if (o == NULL || o->slot == NULL || priv == NULL || privSz == 0)
        return BAD_FUNC_ARG;
    /* Stateful keys are token-resident only - reject any attempt to
     * persist state for a session-only object. The HSS write CB enforces
     * this too, but the framework helper enforces it for all schemes. */
    if (!o->onToken)
        return BAD_FUNC_ARG;
    if (o->statefulStateId == 0)
        return BAD_FUNC_ARG;
    if (schemeParamBytes == NULL && schemeParamLen != 0)
        return BAD_FUNC_ARG;
    /* Defensive caps: prevent size-arithmetic overflow. */
    if (privSz > WP11_STATEFUL_PRIV_MAX)
        return BAD_FUNC_ARG;
    if (schemeParamLen > WP11_STATEFUL_PARAMS_MAX)
        return BAD_FUNC_ARG;

    ctLen = privSz + AES_BLOCK_SIZE;  /* +16 for GCM tag */
    hdrLen = 4 + 4 + 4 + schemeParamLen + 8;
    hdr = (byte*)XMALLOC(hdrLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (hdr == NULL)
        return MEMORY_E;

    wp11_Stateful_WriteU32(hdr + 0, magic);
    wp11_Stateful_WriteU32(hdr + 4, version);
    wp11_Stateful_WriteU32(hdr + 8, schemeParamLen);
    if (schemeParamLen > 0)
        XMEMCPY(hdr + 12, schemeParamBytes, schemeParamLen);
    wp11_Stateful_WriteU64(hdr + 12 + schemeParamLen, o->statefulSigCount);

    /* Fresh GCM nonce per write (NEVER reuse object->iv). */
    ret = WP11_Slot_GenerateRandom(o->slot, iv, WP11_STATEFUL_IV_LEN);
    if (ret != 0) {
        XFREE(hdr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    ct = (byte*)XMALLOC(ctLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ct == NULL) {
        XFREE(hdr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

    ret = wp11_EncryptDataAAD(ct, priv, (int)privSz,
        o->slot->token.key, (int)sizeof(o->slot->token.key),
        iv, WP11_STATEFUL_IV_LEN, hdr, (int)hdrLen, o->devId);
    if (ret != 0) {
        wc_ForceZero(ct, ctLen);
        XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(hdr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    /* total bytes to write: hdr + ivLen u32 + iv + ctLen u32 + ct||tag -
     * unused for file storage, but kept for parity with TPM_STORE. */
    (void)(hdrLen + 4 + WP11_STATEFUL_IV_LEN + 4 + ctLen);

    tokenId = (int)o->slot->id;
    ret = wp11_Stateful_StateFile_Open(schemeFilePrefix, tokenId,
        o->statefulStateId, 0, &storage);
    if (ret == 0) {
        if (wp11_StatefulShouldFsync())
            wolfPKCS11_Store_SetDurable(storage, 1);
        ret = wp11_storage_write(storage, hdr, (int)hdrLen);
        if (ret == 0) {
            byte ivLenBuf[4];
            wp11_Stateful_WriteU32(ivLenBuf, WP11_STATEFUL_IV_LEN);
            ret = wp11_storage_write(storage, ivLenBuf, 4);
        }
        if (ret == 0)
            ret = wp11_storage_write(storage, iv, WP11_STATEFUL_IV_LEN);
        if (ret == 0) {
            byte ctLenBuf[4];
            wp11_Stateful_WriteU32(ctLenBuf, ctLen);
            ret = wp11_storage_write(storage, ctLenBuf, 4);
        }
        if (ret == 0)
            ret = wp11_storage_write(storage, ct, (int)ctLen);
        /* Capture the close-and-commit result. A void close would mask
         * a failed rename/fsync; that would let wolfSSL release a signature
         * whose state advance never reached durable storage. */
        {
            int closeRet = wolfPKCS11_Store_CloseAndReport(storage);
            if (ret == 0)
                ret = closeRet;
        }
    }

    wc_ForceZero(ct, ctLen);
    XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(hdr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Read and decrypt the state file. The full header is verified as AAD by
 * the AES-GCM tag; tampering with magic, version, scheme params, scheme-
 * params length, or the persisted sigCount fails decrypt. The expected
 * scheme params are passed by the caller (typically: re-pack from the
 * in-memory wolfSSL key); a mismatch returns BAD_FUNC_ARG before decrypt.
 * The decrypted sigCount is restored into o->statefulSigCount. */
static int wp11_Stateful_ReadStateBlob(WP11_Object* o,
    const char* schemeFilePrefix, word32 magic, word32 version,
    const byte* expectedSchemeParamBytes, word32 schemeParamLen,
    byte* priv, word32 privSz)
{
    int ret;
    void* storage = NULL;
    byte* hdr = NULL;
    word32 hdrLen;
    byte iv[WP11_STATEFUL_IV_LEN];
    byte* ct = NULL;
    word32 m, v, persistedParamLen, ivLen, ctLen;
    word64 sigCount = 0;
    int tokenId;

    if (o == NULL || priv == NULL || privSz == 0)
        return BAD_FUNC_ARG;
    if (o->statefulStateId == 0)
        return BAD_FUNC_ARG;
    if (expectedSchemeParamBytes == NULL && schemeParamLen != 0)
        return BAD_FUNC_ARG;
    if (privSz > WP11_STATEFUL_PRIV_MAX)
        return BAD_FUNC_ARG;
    if (schemeParamLen > WP11_STATEFUL_PARAMS_MAX)
        return BAD_FUNC_ARG;

    hdrLen = 4 + 4 + 4 + schemeParamLen + 8;
    hdr = (byte*)XMALLOC(hdrLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (hdr == NULL) {
        wc_ForceZero(priv, privSz);
        return MEMORY_E;
    }

    tokenId = (int)o->slot->id;
    ret = wp11_Stateful_StateFile_Open(schemeFilePrefix, tokenId,
        o->statefulStateId, 1, &storage);
    if (ret != 0) {
        XFREE(hdr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        wc_ForceZero(priv, privSz);
        return ret;
    }

    ret = wp11_storage_read(storage, hdr, (int)hdrLen);
    if (ret == 0) {
        m = wp11_Stateful_ReadU32(hdr);
        v = wp11_Stateful_ReadU32(hdr + 4);
        persistedParamLen = wp11_Stateful_ReadU32(hdr + 8);
        sigCount = wp11_Stateful_ReadU64(hdr + 12 + schemeParamLen);
        if (m != magic || v != version) {
            ret = BAD_FUNC_ARG;
        }
        else if (persistedParamLen != schemeParamLen) {
            /* Scheme-params length mismatch - diagnoses thin-wrapper
             * version skew before AES-GCM tag failure. */
            ret = BAD_FUNC_ARG;
        }
        else if (schemeParamLen > 0 &&
                 XMEMCMP(hdr + 12, expectedSchemeParamBytes, schemeParamLen)
                 != 0) {
            ret = BAD_FUNC_ARG;
        }
    }
    if (ret == 0) {
        byte buf[4];
        ret = wp11_storage_read(storage, buf, 4);
        if (ret == 0) {
            ivLen = wp11_Stateful_ReadU32(buf);
            if (ivLen != WP11_STATEFUL_IV_LEN)
                ret = BAD_FUNC_ARG;
        }
    }
    if (ret == 0)
        ret = wp11_storage_read(storage, iv, WP11_STATEFUL_IV_LEN);
    if (ret == 0) {
        byte buf[4];
        ret = wp11_storage_read(storage, buf, 4);
        if (ret == 0) {
            ctLen = wp11_Stateful_ReadU32(buf);
            if (ctLen < AES_BLOCK_SIZE ||
                    ctLen - AES_BLOCK_SIZE != privSz) {
                ret = BAD_FUNC_ARG;
            }
        }
    }
    if (ret == 0) {
        ct = (byte*)XMALLOC(ctLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (ct == NULL)
            ret = MEMORY_E;
    }
    if (ret == 0)
        ret = wp11_storage_read(storage, ct, (int)ctLen);
    if (ret == 0) {
        ret = wp11_DecryptDataAAD(priv, ct, (int)privSz,
            o->slot->token.key, (int)sizeof(o->slot->token.key),
            iv, WP11_STATEFUL_IV_LEN, hdr, (int)hdrLen, o->devId);
        /* AES-GCM authentication failure manifests here. */
    }
    wp11_storage_close(storage);
    if (ct != NULL) {
        wc_ForceZero(ct, ctLen);
        XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    XFREE(hdr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret == 0) {
        /* AES-GCM verified the header; sigCount cannot have been rolled
         * back without detection. Restore into the in-memory object. */
        o->statefulSigCount = sigCount;
    }
    if (ret != 0)
        wc_ForceZero(priv, privSz);
    return ret;
}

/* Recover the per-key stateId from the on-disk shell file. The shell
 * format is otherwise scheme-specific, but by contract the LAST 8 bytes
 * are always the u64 stateId. Used by Unstore to find the state file
 * before deleting it, when the in-memory object hasn't been decoded yet.
 *
 * Validates the shell's magic + version against caller-supplied values
 * before returning the trailer. Without this check, a truncated, replaced,
 * or wrong-scheme file at the same (tokenId, objId) would yield a garbage
 * stateId that the caller then passes to Store_Remove - silently no-op'ing
 * or deleting the wrong file while the real state file orphans on disk.
 *
 * Returns BAD_FUNC_ARG if magic or version don't match (e.g., wrong scheme,
 * file truncated below the header size, or the file is something else). */
static int wp11_Stateful_PeekStateIdFromShell(int tokenId, int objId,
    int storeTypeShell, word32 expectedShellMagic, word32 expectedShellVersion,
    word64* outStateId)
{
    int ret;
    void* storage = NULL;
    unsigned char* buf = NULL;
    int bufLen = 0;

    if (outStateId == NULL)
        return BAD_FUNC_ARG;
    *outStateId = 0;

    ret = wp11_storage_open_readonly(storeTypeShell,
        (CK_ULONG)tokenId, (CK_ULONG)objId, &storage);
    if (ret != 0)
        return ret;
    ret = wp11_storage_read_alloc_array(storage, &buf, &bufLen);
    wp11_storage_close(storage);
    if (ret != 0)
        return ret;

    /* Need at least [u32 magic][u32 version] + [u64 stateId trailer]. */
    if (bufLen < 16) {
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return BAD_FUNC_ARG;
    }
    if (wp11_Stateful_ReadU32(buf) != expectedShellMagic ||
            wp11_Stateful_ReadU32(buf + 4) != expectedShellVersion) {
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return BAD_FUNC_ARG;
    }
    *outStateId = wp11_Stateful_ReadU64(buf + (bufLen - 8));
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}
#endif /* WOLFPKCS11_STATEFUL_SIG_PRIVATE */

#ifdef WOLFPKCS11_LMS
/* ===========================================================================
 * LMS/HSS (RFC 8554): verification and public-key import.
 *
 * Verify-only: this build imports raw HSS public keys and verifies
 * signatures. There is no private-key/keygen/sign or persisted signature
 * state here. The public key is self-describing, so wolfSSL derives the
 * parameter set from the key bytes on import; the CKA_HSS_LEVELS /
 * CKA_HSS_LMS_TYPE / CKA_HSS_LMOTS_TYPE attributes are optional and, when
 * supplied, are validated against the imported key.
 * ========================================================================= */

/* Map tree height -> RFC 8554 LMS typecode. Returns 0 on unknown height. */
static CK_LMS_TYPE wp11_HssHeightToLmsType(int h)
{
    switch (h) {
        case 5:  return CKL_LMS_SHA256_M32_H5;
        case 10: return CKL_LMS_SHA256_M32_H10;
        case 15: return CKL_LMS_SHA256_M32_H15;
        case 20: return CKL_LMS_SHA256_M32_H20;
        case 25: return CKL_LMS_SHA256_M32_H25;
        default: return 0;
    }
}

/* Map Winternitz -> LMOTS typecode. Returns 0 on unknown. */
static CK_LMOTS_TYPE wp11_HssWToLmotsType(int w)
{
    switch (w) {
        case 1: return CKL_LMOTS_SHA256_N32_W1;
        case 2: return CKL_LMOTS_SHA256_N32_W2;
        case 4: return CKL_LMOTS_SHA256_N32_W4;
        case 8: return CKL_LMOTS_SHA256_N32_W8;
        default: return 0;
    }
}

#ifdef WOLFPKCS11_LMS_PRIVATE
/* Forward parameter maps (RFC 8554 typecode -> height / Winternitz), used by
 * keygen to translate the CKA_HSS_LMS_TYPE / CKA_HSS_LMOTS_TYPE attributes.
 * Return 0 on unknown. */
static int wp11_HssLmsTypeToHeight(CK_LMS_TYPE t)
{
    switch (t) {
        case CKL_LMS_SHA256_M32_H5:  return 5;
        case CKL_LMS_SHA256_M32_H10: return 10;
        case CKL_LMS_SHA256_M32_H15: return 15;
        case CKL_LMS_SHA256_M32_H20: return 20;
        case CKL_LMS_SHA256_M32_H25: return 25;
        default:                     return 0;
    }
}

static int wp11_HssLmotsTypeToW(CK_LMOTS_TYPE t)
{
    switch (t) {
        case CKL_LMOTS_SHA256_N32_W1: return 1;
        case CKL_LMOTS_SHA256_N32_W2: return 2;
        case CKL_LMOTS_SHA256_N32_W4: return 4;
        case CKL_LMOTS_SHA256_N32_W8: return 8;
        default:                      return 0;
    }
}

/* On-disk magic + version for the HSS private-key shell file: non-secret
 * metadata (parameters + cached public key) with the 8-byte stateId nonce as
 * the last 8 bytes. Persisted at keygen so token load can call
 * wc_LmsKey_SetParameters before wc_LmsKey_Reload and locate the state file. */
#define WP11_HSS_SHELL_MAGIC      0x48535350UL  /* "HSSP" */
#define WP11_HSS_SHELL_VERSION    1U
/* Fixed part of the shell, ahead of the public key: magic, version, levels,
 * height, winternitz and the public-key length, each a big-endian u32. */
#define WP11_HSS_SHELL_HDR_LEN    (6 * 4)
/* The stateId trailer that wp11_Stateful_PeekStateIdFromShell relies on being
 * the last bytes of the shell. */
#define WP11_HSS_SHELL_TRAILER_LEN 8

/* On-disk magic + version for the encrypted HSS state file. The header
 * (levels/height/winternitz + persisted signature counter) is bound into the
 * AES-GCM tag via AAD, so tampering is detected at decrypt time. */
#define WP11_HSS_STATE_MAGIC      0x48535353UL  /* "HSSS" */
#define WP11_HSS_STATE_VERSION    1U

/* HSS scheme param region inside the AAD-bound state header: 3 u32s. */
#define WP11_HSS_SCHEME_PARAM_LEN 12U

/* Serialize the private-key shell header:
 *   [u32 magic][u32 version][u32 levels][u32 height][u32 winternitz]
 *   [u32 pubLen][pub]. The 8-byte stateId trailer is appended by the caller.
 * Returns bytes written, or BUFFER_E. */
static int wp11_HssPackShellHeader(byte* out, word32 outLen, int levels,
    int height, int winternitz, const byte* pub, word32 pubLen)
{
    word32 needed = WP11_HSS_SHELL_HDR_LEN + pubLen;
    word32 idx = 0;

    if (out == NULL || outLen < needed)
        return BUFFER_E;
    wp11_Stateful_WriteU32(out + idx, (word32)WP11_HSS_SHELL_MAGIC);   idx += 4;
    wp11_Stateful_WriteU32(out + idx, (word32)WP11_HSS_SHELL_VERSION); idx += 4;
    wp11_Stateful_WriteU32(out + idx, (word32)levels);      idx += 4;
    wp11_Stateful_WriteU32(out + idx, (word32)height);      idx += 4;
    wp11_Stateful_WriteU32(out + idx, (word32)winternitz);  idx += 4;
    wp11_Stateful_WriteU32(out + idx, pubLen);              idx += 4;
    if (pub != NULL && pubLen > 0)
        XMEMCPY(out + idx, pub, pubLen);
    idx += pubLen;
    return (int)idx;
}

/* Parse the private-key shell header. On success *pub points into the input
 * buffer (no allocation) and *pubLen is its length. */
static int wp11_HssParseShellHeader(const byte* in, word32 inLen,
    int* levels, int* height, int* winternitz,
    const byte** pub, word32* pubLen)
{
    word32 idx = 0;
    word32 magic, version, pl;

    if (in == NULL || inLen < WP11_HSS_SHELL_HDR_LEN)
        return BAD_FUNC_ARG;
    magic = wp11_Stateful_ReadU32(in + idx);   idx += 4;
    version = wp11_Stateful_ReadU32(in + idx); idx += 4;
    if (magic != WP11_HSS_SHELL_MAGIC || version != WP11_HSS_SHELL_VERSION)
        return BAD_FUNC_ARG;
    *levels = (int)wp11_Stateful_ReadU32(in + idx);     idx += 4;
    *height = (int)wp11_Stateful_ReadU32(in + idx);     idx += 4;
    *winternitz = (int)wp11_Stateful_ReadU32(in + idx); idx += 4;
    pl = wp11_Stateful_ReadU32(in + idx);               idx += 4;
    /* Cap pubLen against the max HSS public-key size so a malformed shell
     * cannot force a giant ImportPubRaw. */
    if (pl > HSS_MAX_PUBLIC_KEY_LEN)
        return BAD_FUNC_ARG;
    if (idx + pl > inLen)
        return BAD_FUNC_ARG;
    *pub = in + idx;
    *pubLen = pl;
    return 0;
}

/* Pack the HSS scheme params (levels|height|winternitz, big-endian u32s) into
 * the AAD-bound region of the state header. */
static void wp11_Hss_PackSchemeParams(byte out[WP11_HSS_SCHEME_PARAM_LEN],
    int levels, int height, int winternitz)
{
    wp11_Stateful_WriteU32(out + 0, (word32)levels);
    wp11_Stateful_WriteU32(out + 4, (word32)height);
    wp11_Stateful_WriteU32(out + 8, (word32)winternitz);
}

/* HSS state-file write, keyed on disk by (slot_id, statefulStateId). Thin
 * wrapper over the generic durable state-blob writer. */
static int wp11_Hss_WriteStateBlob(WP11_Object* o, const byte* priv,
    word32 privSz)
{
    int levels = 0, height = 0, winternitz = 0;
    byte schemeParams[WP11_HSS_SCHEME_PARAM_LEN];
    int ret;

    if (o == NULL || o->data.lmsKey == NULL)
        return BAD_FUNC_ARG;
    ret = wc_LmsKey_GetParameters(o->data.lmsKey, &levels, &height,
        &winternitz);
    if (ret != 0)
        return ret;
    wp11_Hss_PackSchemeParams(schemeParams, levels, height, winternitz);
    return wp11_Stateful_WriteStateBlob(o, "hsskey",
        (word32)WP11_HSS_STATE_MAGIC, WP11_HSS_STATE_VERSION,
        schemeParams, WP11_HSS_SCHEME_PARAM_LEN, priv, privSz);
}

/* HSS state-file read. Validates the in-memory key's params against the
 * AAD-bound header before AES-GCM decrypt. */
static int wp11_Hss_ReadStateBlob(WP11_Object* o, byte* priv, word32 privSz)
{
    int levels = 0, height = 0, winternitz = 0;
    byte schemeParams[WP11_HSS_SCHEME_PARAM_LEN];
    int ret;

    if (o == NULL || o->data.lmsKey == NULL)
        return BAD_FUNC_ARG;
    ret = wc_LmsKey_GetParameters(o->data.lmsKey, &levels, &height,
        &winternitz);
    if (ret != 0)
        return ret;
    wp11_Hss_PackSchemeParams(schemeParams, levels, height, winternitz);
    return wp11_Stateful_ReadStateBlob(o, "hsskey",
        (word32)WP11_HSS_STATE_MAGIC, WP11_HSS_STATE_VERSION,
        schemeParams, WP11_HSS_SCHEME_PARAM_LEN, priv, privSz);
}

/* wolfSSL write callback: invoked by wc_LmsKey_MakeKey and wc_LmsKey_Sign
 * after each state advance. Must return WC_LMS_RC_SAVED_TO_NV_MEMORY on
 * success; any other value aborts the sign (wolfSSL zeroizes the signature). */
static int wp11_Hss_WriteState_Cb(const byte* priv, word32 privSz, void* ctx)
{
    WP11_Object* o = (WP11_Object*)ctx;

    if (o == NULL || priv == NULL || privSz == 0)
        return WC_LMS_RC_BAD_ARG;
    /* Stateful HSS keys are always token-resident in this build. */
    if (!o->onToken || o->statefulStateId == 0)
        return WC_LMS_RC_WRITE_FAIL;
    if (wp11_Hss_WriteStateBlob(o, priv, privSz) != 0)
        return WC_LMS_RC_WRITE_FAIL;
    return WC_LMS_RC_SAVED_TO_NV_MEMORY;
}

static int wp11_Hss_ReadState_Cb(byte* priv, word32 privSz, void* ctx)
{
    WP11_Object* o = (WP11_Object*)ctx;

    if (o == NULL)
        return WC_LMS_RC_BAD_ARG;
    if (wp11_Hss_ReadStateBlob(o, priv, privSz) != 0)
        return WC_LMS_RC_READ_FAIL;
    return WC_LMS_RC_READ_TO_MEMORY;
}

/* Recover the statefulStateId from the on-disk HSS shell (last 8 bytes),
 * validating the shell magic+version first. Used by orphan cleanup when the
 * object has not been decoded into memory. */
static int wp11_Hss_PeekStateIdFromShell(int tokenId, int objId,
    word64* outStateId)
{
    return wp11_Stateful_PeekStateIdFromShell(tokenId, objId,
        WOLFPKCS11_STORE_HSSKEY_PRIV, (word32)WP11_HSS_SHELL_MAGIC,
        WP11_HSS_SHELL_VERSION, outStateId);
}

/* Delete the signature-state file backing a stored HSS private key, called
 * when the object itself is removed from the token. The per-key nonce comes
 * from the in-memory object when it has been decoded, otherwise from the
 * on-disk shell. Best effort: a state file that cannot be located or removed
 * must not stop the object from being destroyed. */
void wp11_Hss_RemoveStoredState(WP11_Object* object, int tokenId, int objId)
{
    word64 stateId;

    if (object == NULL)
        return;

    stateId = object->statefulStateId;
    if (stateId == 0)
        (void)wp11_Hss_PeekStateIdFromShell(tokenId, objId, &stateId);
    if (stateId != 0)
        (void)wp11_Stateful_StateFile_Remove("hsskey", tokenId, stateId);
}
#endif /* WOLFPKCS11_LMS_PRIVATE */

/* Import a raw HSS public key into the given wolfSSL LmsKey. wolfSSL derives
 * the parameter set from the key bytes (RFC 8554 self-describing public key),
 * so no parameters need to be set first. On failure the (partially
 * initialized) key is NOT freed here; the caller owns it. */
static int wp11_HssImportPub(LmsKey* key, int devId, const byte* pub,
    word32 pubLen)
{
    int ret;

    ret = wc_LmsKey_Init(key, NULL, devId);
    if (ret == 0)
        ret = wc_LmsKey_ImportPubRaw(key, pub, pubLen);
    return ret;
}

/* Validate caller-supplied HSS parameter attributes against the parameters
 * wolfSSL derived from the just-imported public key. Per the PKCS#11 v3.3 HSS
 * profile the public-key parameters are the individual CK_ULONG attributes
 * CKA_HSS_LEVELS, CKA_HSS_LMS_TYPE (top-level tree height encoding) and
 * CKA_HSS_LMOTS_TYPE (Winternitz encoding). Each is optional; a supplied value
 * that does not match the key is rejected with BAD_FUNC_ARG. levelsAttr,
 * lmsAttr and lmotsAttr are the raw attribute buffers (NULL when absent) with
 * lengths levelsLen/lmsLen/lmotsLen. */
static int wp11_HssCheckParamAttrs(LmsKey* key,
    const byte* levelsAttr, word32 levelsLen,
    const byte* lmsAttr, word32 lmsLen,
    const byte* lmotsAttr, word32 lmotsLen)
{
    int ret, levels = 0, height = 0, winternitz = 0;
    CK_ULONG v;

    ret = wc_LmsKey_GetParameters(key, &levels, &height, &winternitz);
    if (ret != 0)
        return ret;
    if (levelsAttr != NULL) {
        if (levelsLen != sizeof(v))
            return BAD_FUNC_ARG;
        XMEMCPY(&v, levelsAttr, sizeof(v));
        if (v != (CK_ULONG)levels)
            return BAD_FUNC_ARG;
    }
    if (lmsAttr != NULL) {
        if (lmsLen != sizeof(v))
            return BAD_FUNC_ARG;
        XMEMCPY(&v, lmsAttr, sizeof(v));
        if (v != (CK_ULONG)wp11_HssHeightToLmsType(height))
            return BAD_FUNC_ARG;
    }
    if (lmotsAttr != NULL) {
        if (lmotsLen != sizeof(v))
            return BAD_FUNC_ARG;
        XMEMCPY(&v, lmotsAttr, sizeof(v));
        if (v != (CK_ULONG)wp11_HssWToLmotsType(winternitz))
            return BAD_FUNC_ARG;
    }
    return 0;
}

/* Serialize the public key: keyData holds the raw RFC 8554 HSS public key. */
int wp11_Object_Encode_HssKey(WP11_Object* object)
{
    int ret;
    word32 pubLen = 0;

    if (object->objClass == CKO_PUBLIC_KEY) {
        /* Public key: raw RFC 8554 public key, unencrypted (Step-1 format). */
        ret = wc_LmsKey_GetPubLen(object->data.lmsKey, &pubLen);
        if (ret == 0) {
            XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            object->keyData = (unsigned char*)XMALLOC(pubLen, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (object->keyData == NULL)
                ret = MEMORY_E;
        }
        if (ret == 0) {
            ret = wc_LmsKey_ExportPubRaw(object->data.lmsKey, object->keyData,
                &pubLen);
            if (ret == 0)
                object->keyDataLen = (int)pubLen;
        }
        /* On failure release the buffer so a later store does not skip
         * re-encoding and persist an uninitialised buffer. Public key material
         * only, so no zeroization needed. */
        if (ret != 0) {
            XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            object->keyData = NULL;
            object->keyDataLen = 0;
        }
        return ret;
    }
#ifdef WOLFPKCS11_LMS_PRIVATE
    if (object->objClass == CKO_PRIVATE_KEY) {
        /* Private key: a non-secret metadata shell (params + cached public
         * key + 8-byte stateId trailer). The secret one-time-signature state
         * is NEVER written to keyData - it lives only in the AES-GCM state
         * file written by the wolfSSL write callback.
         *
         * The shell is immutable after keygen. Once materialized (built at
         * keygen, or loaded from disk), reuse it: a reloaded signing key
         * cannot re-export its public root (wolfSSL keeps a key in either
         * signing or verify state), so rebuilding here would fail. */
        int levels = 0, height = 0, winternitz = 0;
        byte pub[HSS_MAX_PUBLIC_KEY_LEN];
        int hdrLen;
        word32 needed;

        if (object->keyData != NULL && object->keyDataLen > 0)
            return 0;

        pubLen = sizeof(pub);
        ret = wc_LmsKey_GetParameters(object->data.lmsKey, &levels, &height,
            &winternitz);
        if (ret == 0)
            ret = wc_LmsKey_ExportPubRaw(object->data.lmsKey, pub, &pubLen);
        if (ret == 0 && object->statefulStateId == 0)
            ret = BAD_FUNC_ARG;
        if (ret == 0) {
            needed = WP11_HSS_SHELL_HDR_LEN + pubLen +
                WP11_HSS_SHELL_TRAILER_LEN;
            XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            object->keyData = (unsigned char*)XMALLOC(needed, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (object->keyData == NULL)
                ret = MEMORY_E;
        }
        if (ret == 0) {
            hdrLen = wp11_HssPackShellHeader(object->keyData, needed, levels,
                height, winternitz, pub, pubLen);
            if (hdrLen < 0) {
                ret = hdrLen;
            }
            else {
                wp11_Stateful_WriteU64(object->keyData + hdrLen,
                    object->statefulStateId);
                object->keyDataLen = hdrLen + 8;
            }
        }
        wc_ForceZero(pub, sizeof(pub));
        if (ret != 0) {
            XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            object->keyData = NULL;
            object->keyDataLen = 0;
        }
        return ret;
    }
#endif
    return NOT_AVAILABLE_E;
}

/* Reconstruct the live wolfSSL key from keyData. Public keys import the raw
 * key directly; private keys parse the shell, reload the durable signature
 * state (via the read callback), and mark the state valid. */
int wp11_Object_Decode_HssKey(WP11_Object* object)
{
    int ret;

    if (object->objClass == CKO_PUBLIC_KEY) {
        /* Raw RFC 8554 public key; wolfSSL re-derives the parameter set. */
        ret = wp11_HssImportPub(object->data.lmsKey, object->devId,
            object->keyData, (word32)object->keyDataLen);
        object->encoded = (ret != 0) ? 1 : 0;
        return ret;
    }
#ifdef WOLFPKCS11_LMS_PRIVATE
    if (object->objClass == CKO_PRIVATE_KEY) {
        int levels = 0, height = 0, winternitz = 0;
        const byte* pub = NULL;
        word32 pubLen = 0;
        word32 idx = 0;

        ret = wp11_HssParseShellHeader(object->keyData,
            (word32)object->keyDataLen, &levels, &height, &winternitz,
            &pub, &pubLen);
        if (ret == 0) {
            idx = WP11_HSS_SHELL_HDR_LEN + pubLen; /* trailer follows pub */
            if (idx + WP11_HSS_SHELL_TRAILER_LEN > (word32)object->keyDataLen)
                ret = BAD_FUNC_ARG;
        }
        if (ret == 0) {
            object->statefulStateId =
                wp11_Stateful_ReadU64(object->keyData + idx);
            if (object->statefulStateId == 0)
                ret = BAD_FUNC_ARG;
        }
        /* INVALID_DEVID unconditionally (not object->devId): HSS stateful
         * signing is software-only by design - HSM/device-backed LMS is out of
         * scope. This must hold even when the slot has a real devId (a hardware-
         * offload build), so it is pinned here rather than inheriting the slot
         * default. A real devId would route to the crypto callback and make
         * wc_LmsKey_Reload treat the key as HSM-backed and skip the read
         * callback (a no-op), leaving the reloaded key with no private state -
         * any later Sign would then reuse leaf index 0 or crash. */
        if (ret == 0)
            ret = wc_LmsKey_Init(object->data.lmsKey, NULL, INVALID_DEVID);
        if (ret == 0)
            ret = wc_LmsKey_SetParameters(object->data.lmsKey, levels, height,
                winternitz);
        /* Wire callbacks before Reload: Reload reads the encrypted state via
         * the read callback; the write callback is needed for later signing. */
        if (ret == 0)
            ret = wc_LmsKey_SetWriteCb(object->data.lmsKey,
                wp11_Hss_WriteState_Cb);
        if (ret == 0)
            ret = wc_LmsKey_SetReadCb(object->data.lmsKey,
                wp11_Hss_ReadState_Cb);
        if (ret == 0)
            ret = wc_LmsKey_SetContext(object->data.lmsKey, object);
        if (ret == 0)
            ret = wc_LmsKey_Reload(object->data.lmsKey);
        /* Do NOT ImportPubRaw here: wolfSSL keeps an LmsKey in either signing
         * (reloaded) or verify (pub) state, not both, and rejects a pub import
         * after Reload with BAD_STATE_E. The public root is not needed for
         * signing, and the cached shell (kept in keyData) preserves it for
         * re-storage. */
        (void)pub;
        if (ret == 0) {
            object->opFlag |= WP11_FLAG_STATEFUL_STATE_VALID;
            object->encoded = 0;
        }
        else {
            /* Clear the validity flag so a later Sign cannot use a half-built
             * key, and free the wolfSSL key. encoded=1 stops Object_Free from
             * freeing the wolfSSL key a second time. */
            object->opFlag &= ~WP11_FLAG_STATEFUL_STATE_VALID;
            wc_LmsKey_Free(object->data.lmsKey);
            object->encoded = 1;
        }
        return ret;
    }
#endif
    return NOT_AVAILABLE_E;
}

int wp11_Object_Load_HssKey(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;
    int storeType = WOLFPKCS11_STORE_HSSKEY_PUB;

#ifdef WOLFPKCS11_LMS_PRIVATE
    if (object->objClass == CKO_PRIVATE_KEY)
        storeType = WOLFPKCS11_STORE_HSSKEY_PRIV;
#endif
    ret = wp11_storage_open_readonly(storeType, tokenId, objId, &storage);
    if (ret == 0) {
        ret = wp11_storage_read_alloc_array(storage, &object->keyData,
            &object->keyDataLen);
        wp11_storage_close(storage);
    }
    return ret;
}

int wp11_Object_Store_HssKey(WP11_Object* object, int tokenId, int objId)
{
    int ret = 0;
    void* storage = NULL;
    int storeType = WOLFPKCS11_STORE_HSSKEY_PUB;

#ifdef WOLFPKCS11_LMS_PRIVATE
    if (object->objClass == CKO_PRIVATE_KEY)
        storeType = WOLFPKCS11_STORE_HSSKEY_PRIV;
#endif
    if (object->keyData == NULL)
        ret = wp11_Object_Encode_HssKey(object);
    if (ret == 0)
        ret = wp11_storage_open(storeType, tokenId, objId,
            object->keyDataLen, &storage);
    if (ret == 0) {
        ret = wp11_storage_write_array(storage, object->keyData,
            object->keyDataLen);
        wp11_storage_close(storage);
    }
    return ret;
}

/* Import an HSS public key from a C_CreateObject template. Following the
 * PKCS#11 v3.3 HSS profile the collected attributes are data[0]=CKA_HSS_LEVELS,
 * data[1]=CKA_HSS_LMS_TYPE, data[2]=CKA_HSS_LMOTS_TYPE (all optional CK_ULONG)
 * and data[3]=CKA_VALUE, the raw RFC 8554 public key. wolfSSL derives the
 * parameter set from the key bytes; any supplied CKA_HSS_* attribute is
 * validated against the derived parameters and a mismatch is rejected.
 * Private-key import is rejected: caller-supplied stateful private material is
 * a forgery vector and out of scope for verify-only support. */
int WP11_Object_SetHssKey(WP11_Object* object, unsigned char** data,
                          CK_ULONG* len)
{
    int ret = 0;
    LmsKey* newKey = NULL;

    if (object == NULL || data == NULL || len == NULL)
        return BAD_FUNC_ARG;
#ifdef WOLFPKCS11_LMS_PRIVATE
    /* Keygen (C_GenerateKeyPair) creates both objects with no CKA_VALUE and
     * populates them in WP11_Hss_GenerateKeyPair, so a missing value is a
     * deferred keygen object, not an error. A private key must never be
     * imported WITH a value: caller-supplied one-time-signature state is a
     * forgery vector. */
    if (object->objClass == CKO_PRIVATE_KEY) {
        if (data[3] != NULL)
            return BAD_FUNC_ARG;
        return 0;
    }
    if (object->objClass != CKO_PUBLIC_KEY)
        return BAD_FUNC_ARG;
    if (data[3] == NULL)
        return 0;
#else
    if (object->objClass != CKO_PUBLIC_KEY)
        return BAD_FUNC_ARG;
    /* A public key must carry its value. There is no keygen path in a
     * verify-only build that would populate it later, so an absent
     * CKA_VALUE is an incomplete template rather than a deferred import;
     * reject it instead of creating an unusable object. */
    if (data[3] == NULL)
        return BAD_FUNC_ARG;
#endif

    if (object->onToken)
        WP11_Lock_LockRW(object->lock);

    /* Import into a temporary key and swap it in only after it fully validates,
     * so a failed re-import (C_SetAttributeValue with a new CKA_VALUE) leaves
     * the existing key unchanged as PKCS#11 requires. */
    newKey = (LmsKey*)XMALLOC(sizeof(LmsKey), NULL, DYNAMIC_TYPE_KEY);
    if (newKey == NULL)
        ret = MEMORY_E;
    if (ret == 0) {
        XMEMSET(newKey, 0, sizeof(LmsKey));
        ret = wp11_HssImportPub(newKey, object->devId, data[3],
            (word32)len[3]);
    }
    if (ret == 0) {
        ret = wp11_HssCheckParamAttrs(newKey, data[0], (word32)len[0],
            data[1], (word32)len[1], data[2], (word32)len[2]);
    }
    if (ret == 0) {
        /* Replace the live key and drop the cached serialization so a later
         * store re-encodes from the new key instead of persisting stale bytes. */
        if (object->data.lmsKey != NULL) {
            if (!object->encoded)
                wc_LmsKey_Free(object->data.lmsKey);
            XFREE(object->data.lmsKey, NULL, DYNAMIC_TYPE_KEY);
        }
        object->data.lmsKey = newKey;
        object->encoded = 0;
        newKey = NULL;
        XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        object->keyData = NULL;
        object->keyDataLen = 0;
    }
    if (newKey != NULL) {
        wc_LmsKey_Free(newKey);
        XFREE(newKey, NULL, DYNAMIC_TYPE_KEY);
    }

    if (object->onToken)
        WP11_Lock_UnlockRW(object->lock);
    return ret;
}

/* Verify an HSS signature over a raw message. Stateless on the verifier. */
int WP11_Hss_Verify(unsigned char* sig, word32 sigLen, unsigned char* data,
                    word32 dataLen, int* stat, WP11_Object* pub)
{
    int ret;
    word32 expSigLen = 0;

    if (pub == NULL || pub->data.lmsKey == NULL || stat == NULL)
        return BAD_FUNC_ARG;

    /* Verification only reads the key: wc_LmsKey_Verify works from a locally
     * allocated LmsState, so a shared RO lock is safe for concurrent verifies
     * on the same token object. */
    if (pub->onToken)
        WP11_Lock_LockRO(pub->lock);

    /* A signature whose length does not match the key's parameter set cannot
     * be valid; report it as an invalid signature (stat = 0 ->
     * CKR_SIGNATURE_INVALID) rather than letting wolfSSL's length check
     * surface as a function failure. */
    if (wc_LmsKey_GetSigLen(pub->data.lmsKey, &expSigLen) == 0 &&
            sigLen != expSigLen) {
        *stat = 0;
        ret = 0;
    }
    else {
        /* Unlike XMSS, whose wolfSSL verify rejects a zero-length message with
         * BAD_FUNC_ARG, wc_LmsKey_Verify accepts an empty message, so HSS needs
         * no dataLen == 0 special-case here (see WP11_Xmss_Verify). */
        ret = wc_LmsKey_Verify(pub->data.lmsKey, sig, sigLen, data,
            (int)dataLen);
        /* Only a genuine verification mismatch (SIG_VERIFY_E) maps to stat=0.
         * Remaining argument/state errors surface as a function failure so
         * they are not silently reported as an invalid signature. */
        if (ret == 0) {
            *stat = 1;
        }
        else if (ret == SIG_VERIFY_E) {
            *stat = 0;
            ret = 0;
        }
        else {
            *stat = 0;
        }
    }

    if (pub->onToken)
        WP11_Lock_UnlockRO(pub->lock);

    return ret;
}

#ifdef WOLFPKCS11_LMS_PRIVATE
/* Generate an HSS key pair. levels/lmsType/lmotsType come from the v3.3
 * keygen template attributes; wolfSSL requires uniform parameters across
 * levels. The private key's one-time-signature state is durably persisted at
 * genesis (via the write callback invoked inside wc_LmsKey_MakeKey) before
 * this returns success. */
int WP11_Hss_GenerateKeyPair(WP11_Object* pub, WP11_Object* priv,
                             CK_ULONG levels, CK_LMS_TYPE lmsType,
                             CK_LMOTS_TYPE lmotsType, WP11_Slot* slot)
{
    int ret;
    int nLevels, height, winternitz;
    WC_RNG rng;
    byte pubBuf[HSS_MAX_PUBLIC_KEY_LEN];
    word32 pubLen = sizeof(pubBuf);
    int stateWritten = 0;

    if (pub == NULL || priv == NULL || slot == NULL ||
            pub->data.lmsKey == NULL || priv->data.lmsKey == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Translate the v3.3 typecodes to wolfSSL (levels, height, winternitz),
     * enforcing the wolfSSL level limit. */
    nLevels = (int)levels;
    height = wp11_HssLmsTypeToHeight(lmsType);
    winternitz = wp11_HssLmotsTypeToW(lmotsType);
    if (nLevels < 1 || nLevels > LMS_MAX_LEVELS || height == 0 ||
            winternitz == 0) {
        return BAD_FUNC_ARG;
    }

    /* Generate the per-key 64-bit nonce keying the state file. Must be
     * non-zero (0 is the "none" sentinel); retry on the vanishing chance of
     * zero, else treat as an RNG failure. */
    {
        byte nonceBuf[8];
        int tries;
        for (tries = 0; tries < 4; tries++) {
            ret = WP11_Slot_GenerateRandom(slot, nonceBuf, sizeof(nonceBuf));
            if (ret != 0)
                return ret;
            priv->statefulStateId = wp11_Stateful_ReadU64(nonceBuf);
            if (priv->statefulStateId != 0)
                break;
        }
        if (priv->statefulStateId == 0)
            return RNG_FAILURE_E;
    }

    /* Mark on-token so the write CB commits; AddObject formalizes the
     * registration shortly. priv->lock is assigned later by Session_AddObject;
     * during keygen no other thread holds a handle, so the CB fires unlocked. */
    priv->onToken = 1;
    priv->statefulSigCount = 0;

    /* INVALID_DEVID unconditionally (not priv->devId): HSS stateful signing is
     * software-only by design - HSM/device-backed LMS is out of scope - so this
     * is pinned even when the slot has a real devId (a hardware-offload build),
     * mirroring the reload path in wp11_Object_Decode_HssKey. A real devId would
     * route MakeKey/Sign through the crypto callback and, critically, make a
     * later wc_LmsKey_Reload a no-op, so the persisted state could never be
     * restored. */
    ret = wc_LmsKey_Init(priv->data.lmsKey, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_LmsKey_SetParameters(priv->data.lmsKey, nLevels, height,
            winternitz);
    /* Wire callbacks BEFORE MakeKey so genesis state is persisted durably. */
    if (ret == 0)
        ret = wc_LmsKey_SetWriteCb(priv->data.lmsKey, wp11_Hss_WriteState_Cb);
    if (ret == 0)
        ret = wc_LmsKey_SetReadCb(priv->data.lmsKey, wp11_Hss_ReadState_Cb);
    if (ret == 0)
        ret = wc_LmsKey_SetContext(priv->data.lmsKey, priv);

    if (ret == 0)
        ret = Rng_New(&slot->token.rng, &slot->token.rngLock, &rng);
    if (ret == 0) {
        /* MakeKey invokes the write CB to persist genesis state; on success
         * the genesis state file is durable on disk. */
        ret = wc_LmsKey_MakeKey(priv->data.lmsKey, &rng);
        Rng_Free(&rng);
        if (ret == 0)
            stateWritten = 1;
    }

    /* Mirror parameters + public key into the public-key object. */
    if (ret == 0)
        ret = wc_LmsKey_ExportPubRaw(priv->data.lmsKey, pubBuf, &pubLen);
    if (ret == 0)
        ret = wc_LmsKey_Init(pub->data.lmsKey, NULL, pub->devId);
    if (ret == 0)
        ret = wc_LmsKey_SetParameters(pub->data.lmsKey, nLevels, height,
            winternitz);
    if (ret == 0)
        ret = wc_LmsKey_ImportPubRaw(pub->data.lmsKey, pubBuf, pubLen);

    if (ret == 0) {
        priv->local = pub->local = 1;
        priv->keyGenMech = pub->keyGenMech = CKM_HSS_KEY_PAIR_GEN;
        priv->opFlag |= WP11_FLAG_STATEFUL_STATE_VALID;
    }
    else {
        wc_LmsKey_Free(priv->data.lmsKey);
        /* Mark encoded so the C_GenerateKeyPair cleanup (WP11_Object_Free) does
         * not free the wolfSSL key a second time; mirrors the failure path in
         * wp11_Object_Decode_HssKey. */
        priv->encoded = 1;
        if (stateWritten && priv->statefulStateId != 0) {
            (void)wp11_Stateful_StateFile_Remove("hsskey", (int)slot->id,
                priv->statefulStateId);
        }
        priv->statefulStateId = 0;
    }

    wc_ForceZero(pubBuf, sizeof(pubBuf));
    return ret;
}

/* Remove the durable signature-state file backing an HSS private key that was
 * generated but never committed to the token - e.g. a later C_GenerateKeyPair
 * step (AddObject/SetInitialStates/store) failed after keygen already wrote the
 * genesis state to disk. Without this the encrypted state file is orphaned.
 * No-op unless priv is a CKK_HSS private key with a live state id; safe to call
 * on any object and more than once. */
void WP11_Hss_RemoveOrphanState(WP11_Object* priv, WP11_Slot* slot)
{
    if (priv != NULL && slot != NULL && priv->type == CKK_HSS &&
            priv->objClass == CKO_PRIVATE_KEY && priv->statefulStateId != 0) {
        (void)wp11_Stateful_StateFile_Remove("hsskey", (int)slot->id,
            priv->statefulStateId);
        priv->statefulStateId = 0;
    }
}

/* Sign a raw message with an HSS private key. State is advanced and persisted
 * (via the write CB inside wc_LmsKey_Sign) BEFORE the signature is returned.
 * On any failure the in-memory state is poisoned (STATE_VALID cleared) to
 * force a reload from durable storage before the next attempt. Token-resident
 * keys always have priv->lock == &token->lock. */
int WP11_Hss_Sign(unsigned char* data, word32 dataLen, unsigned char* sig,
                  word32* sigLen, WP11_Object* priv)
{
    int ret = 0;
    word32 outLen = 0;

    if (priv == NULL || priv->data.lmsKey == NULL || sig == NULL ||
            sigLen == NULL || priv->lock == NULL) {
        return BAD_FUNC_ARG;
    }

    WP11_Lock_LockRW(priv->lock);

    if ((priv->opFlag & WP11_FLAG_STATEFUL_STATE_VALID) == 0) {
        ret = NOT_AVAILABLE_E;  /* C-layer maps to CKR_DEVICE_ERROR */
    }
    if (ret == 0) {
        word64 prevCount = priv->statefulSigCount;
        priv->statefulSigCount = prevCount + 1;
        outLen = *sigLen;
        ret = wc_LmsKey_Sign(priv->data.lmsKey, sig, &outLen, data,
            (int)dataLen);
        if (ret == 0) {
            *sigLen = outLen;
        }
        else {
            /* Write CB failed (durable state may lag the in-memory advance)
             * or the key is exhausted. Poison until reloaded; zero any bytes
             * wolfSSL wrote and revert the in-memory counter. */
            priv->opFlag &= ~WP11_FLAG_STATEFUL_STATE_VALID;
            if (outLen > 0)
                XMEMSET(sig, 0, outLen);
            priv->statefulSigCount = prevCount;
        }
    }

    WP11_Lock_UnlockRW(priv->lock);
    return ret;
}

/* Signature length for an HSS private key (parameter-set dependent). Returns
 * 0 on error. */
word32 WP11_Hss_SigLen(WP11_Object* key)
{
    word32 sigLen = 0;

    if (key == NULL || key->data.lmsKey == NULL)
        return 0;
    if (wc_LmsKey_GetSigLen(key->data.lmsKey, &sigLen) != 0)
        return 0;
    return sigLen;
}

/* Remaining one-time keys for an HSS private key. The count comes from the
 * wp11-layer statefulSigCount (persisted in the GCM-authenticated state
 * header) rather than from wolfSSL LmsKey internals, whose layout is not
 * public API: total = 2^(levels*height), saturating at UINT32_MAX for large
 * parameter sets.
 *
 * wolfSSL's own view is used as a cross-check. wc_LmsKey_SigsLeft only reports
 * whether any key is left, so the two can be compared but not reconciled; on
 * disagreement the answer is always the pessimistic one, since over-reporting
 * would invite a caller to attempt a signature that must not happen. */
int WP11_Hss_SigsLeft(WP11_Object* key, word32* remaining)
{
    int levels = 0, height = 0, winternitz = 0;
    int totalH;
    word64 used, total;

    if (key == NULL || key->data.lmsKey == NULL || remaining == NULL)
        return BAD_FUNC_ARG;

    *remaining = 0;

    /* wolfSSL says the key is spent: report 0 whatever the counter holds. */
    if (wc_LmsKey_SigsLeft(key->data.lmsKey) == 0)
        return 0;

    if (wc_LmsKey_GetParameters(key->data.lmsKey, &levels, &height,
            &winternitz) != 0) {
        return BAD_FUNC_ARG;
    }
    totalH = levels * height;
    if (totalH <= 0)
        return BAD_FUNC_ARG;
    if (totalH >= 64) {
        *remaining = 0xFFFFFFFFU;
        return 0;
    }
    total = ((word64)1) << totalH;
    used = key->statefulSigCount;
    /* The counter says spent while wolfSSL still reports keys left. The two
     * views of the state have drifted, so keep the pessimistic 0. */
    if (used >= total)
        return 0;

    if ((total - used) > 0xFFFFFFFFULL)
        *remaining = 0xFFFFFFFFU;
    else
        *remaining = (word32)(total - used);
    return 0;
}
#endif /* WOLFPKCS11_LMS_PRIVATE */

#ifdef WOLFPKCS11_LMS_PRIVATE
/* Serve CKA_HSS_KEYS_REMAINING for a private key. Follows the usual attribute
 * convention: data == NULL asks for the size only, a short buffer returns
 * BUFFER_E with the required size in len. */
static int wp11_HssGetKeysRemaining(WP11_Object* object, byte* data,
                                    CK_ULONG* len)
{
    word32 remaining = 0;
    CK_ULONG v;

    if (WP11_Hss_SigsLeft(object, &remaining) != 0)
        return NOT_AVAILABLE_E;

    v = (CK_ULONG)remaining;
    if (data == NULL) {
        *len = sizeof(v);
        return 0;
    }
    if (*len < sizeof(v)) {
        *len = sizeof(v);
        return BUFFER_E;
    }
    XMEMCPY(data, &v, sizeof(v));
    *len = sizeof(v);
    return 0;
}
#endif /* WOLFPKCS11_LMS_PRIVATE */

/* Serve HSS-specific attributes from a public-key object. */
int HssObject_GetAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type,
                             byte* data, CK_ULONG* len)
{
    int ret = 0;
    int levels = 0, height = 0, winternitz = 0;

    if (object == NULL || object->data.lmsKey == NULL || len == NULL)
        return BAD_FUNC_ARG;

    switch (type) {
        case CKA_HSS_LEVELS: {
            CK_ULONG v;
            ret = wc_LmsKey_GetParameters(object->data.lmsKey, &levels,
                &height, &winternitz);
            if (ret == 0) {
                v = (CK_ULONG)levels;
                if (data == NULL)
                    *len = sizeof(v);
                else if (*len < sizeof(v)) {
                    *len = sizeof(v);
                    ret = BUFFER_E;
                }
                else {
                    XMEMCPY(data, &v, sizeof(v));
                    *len = sizeof(v);
                }
            }
            break;
        }
        case CKA_HSS_LMS_TYPE: {
            CK_LMS_TYPE v;
            ret = wc_LmsKey_GetParameters(object->data.lmsKey, &levels,
                &height, &winternitz);
            if (ret == 0) {
                v = wp11_HssHeightToLmsType(height);
                if (v == 0)
                    ret = NOT_AVAILABLE_E;
                else if (data == NULL)
                    *len = sizeof(v);
                else if (*len < sizeof(v)) {
                    *len = sizeof(v);
                    ret = BUFFER_E;
                }
                else {
                    XMEMCPY(data, &v, sizeof(v));
                    *len = sizeof(v);
                }
            }
            break;
        }
        case CKA_HSS_LMOTS_TYPE: {
            CK_LMOTS_TYPE v;
            ret = wc_LmsKey_GetParameters(object->data.lmsKey, &levels,
                &height, &winternitz);
            if (ret == 0) {
                v = wp11_HssWToLmotsType(winternitz);
                if (v == 0)
                    ret = NOT_AVAILABLE_E;
                else if (data == NULL)
                    *len = sizeof(v);
                else if (*len < sizeof(v)) {
                    *len = sizeof(v);
                    ret = BUFFER_E;
                }
                else {
                    XMEMCPY(data, &v, sizeof(v));
                    *len = sizeof(v);
                }
            }
            break;
        }
        case CKA_HSS_LMS_TYPES:
        case CKA_HSS_LMOTS_TYPES: {
            /* wolfSSL uses uniform LMS/LMOTS parameters across all HSS levels, so
             * every array entry is the top-level type. Per-level types (allowed
             * by the PKCS#11 v3.3 profile) are not expressible by wolfSSL and are
             * not supported here. */
            CK_ULONG total;
            CK_ULONG fill;
            int i;
            ret = wc_LmsKey_GetParameters(object->data.lmsKey, &levels,
                &height, &winternitz);
            if (ret == 0) {
                total = (CK_ULONG)(sizeof(CK_ULONG) * levels);
                fill = (type == CKA_HSS_LMS_TYPES)
                    ? wp11_HssHeightToLmsType(height)
                    : wp11_HssWToLmotsType(winternitz);
                if (fill == 0)
                    ret = NOT_AVAILABLE_E;
                else if (data == NULL)
                    *len = total;
                else if (*len < total) {
                    *len = total;
                    ret = BUFFER_E;
                }
                else {
                    for (i = 0; i < levels; i++)
                        XMEMCPY(data + i * sizeof(CK_ULONG), &fill,
                            sizeof(CK_ULONG));
                    *len = total;
                }
            }
            break;
        }
        case CKA_HSS_KEYS_REMAINING:
            /* Remaining-signature count is a private-key/state property. In a
             * verify-only build (or for a public key) it is unavailable. */
            ret = NOT_AVAILABLE_E;
#ifdef WOLFPKCS11_LMS_PRIVATE
            if (object->objClass == CKO_PRIVATE_KEY)
                ret = wp11_HssGetKeysRemaining(object, data, len);
#endif
            break;
        case CKA_VALUE:
            if (object->objClass == CKO_PUBLIC_KEY) {
                word32 pubLen = 0;
                ret = wc_LmsKey_GetPubLen(object->data.lmsKey, &pubLen);
                if (ret == 0) {
                    if (data == NULL)
                        *len = pubLen;
                    else if (*len < pubLen) {
                        *len = pubLen;
                        ret = BUFFER_E;
                    }
                    else {
                        ret = wc_LmsKey_ExportPubRaw(object->data.lmsKey,
                            data, &pubLen);
                        if (ret == 0)
                            *len = pubLen;
                    }
                }
            }
            else {
                *len = CK_UNAVAILABLE_INFORMATION;
                ret = NOT_AVAILABLE_E;
            }
            break;
        default:
            ret = NOT_AVAILABLE_E;
            break;
    }
    return ret;
}

/* Validate a supplied CKA_HSS_LMS_TYPES / CKA_HSS_LMOTS_TYPES array against the
 * imported public key. wolfSSL uses uniform LMS/LMOTS parameters across all HSS
 * levels, so a conforming array holds one CK_ULONG per level, each equal to the
 * single top-level type served by HssObject_GetAttr. A wrong length or any
 * differing entry is rejected so a malformed or mismatched template is not
 * silently accepted; a matching array (as read back from this key) is accepted.
 * Returns 0 when the array matches, BAD_FUNC_ARG otherwise. The caller holds the
 * object lock. */
int wp11_HssCheckTypesAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type,
                                  const byte* data, CK_ULONG len)
{
    int ret;
    int levels = 0;
    int height = 0;
    int winternitz = 0;
    int i;
    CK_ULONG expected;
    CK_ULONG entry;

    if (object->data.lmsKey == NULL || data == NULL)
        return BAD_FUNC_ARG;

    ret = wc_LmsKey_GetParameters(object->data.lmsKey, &levels, &height,
        &winternitz);
    if (ret != 0)
        return ret;

    expected = (type == CKA_HSS_LMS_TYPES)
        ? (CK_ULONG)wp11_HssHeightToLmsType(height)
        : (CK_ULONG)wp11_HssWToLmotsType(winternitz);
    if (expected == 0)
        return BAD_FUNC_ARG;
    if (len != (CK_ULONG)(sizeof(CK_ULONG) * levels))
        return BAD_FUNC_ARG;

    for (i = 0; i < levels; i++) {
        XMEMCPY(&entry, data + i * sizeof(CK_ULONG), sizeof(entry));
        if (entry != expected)
            return BAD_FUNC_ARG;
    }

    return 0;
}
#endif /* WOLFPKCS11_LMS */

#ifdef WOLFPKCS11_XMSS
/* ===========================================================================
 * XMSS/XMSS^MT (RFC 8391): verification and public-key import.
 *
 * Verify-only. One wolfSSL XmssKey type serves both XMSS and XMSS^MT; the
 * PKCS#11 key type (CKK_XMSS vs CKK_XMSSMT) selects which via the is_xmssmt
 * flag. The raw public key carries the parameter-set OID in its leading
 * bytes, so wc_XmssKey_ImportPubRaw_ex derives the parameter set on import.
 * A CKA_PARAMETER_SET attribute is optional and, when supplied, is validated
 * against the OID in the key.
 * ========================================================================= */

/* Length of the parameter-set OID prefix in a raw RFC 8391 public key. wolfSSL
 * only exposes XMSS_OID_LEN when built with WOLFSSL_HAVE_XMSS and it is absent
 * from some released headers, so define our own to keep the build independent
 * of the wolfSSL version. */
#define WP11_XMSS_OID_LEN 4

/* Big-endian 32-bit read from a byte buffer (used to read the XMSS OID). */
static word32 wp11_HbsReadU32(const byte* p)
{
    return ((word32)p[0] << 24) | ((word32)p[1] << 16)
         | ((word32)p[2] << 8)  |  (word32)p[3];
}

/* Import a raw XMSS/XMSS^MT public key into the given wolfSSL XmssKey, deriving
 * the parameter set from the embedded OID. is_xmssmt disambiguates the XMSS and
 * XMSS^MT OID namespaces (which overlap) and comes from the PKCS#11 key type.
 * When the caller supplies a CKA_PARAMETER_SET (params != NULL, the OID as a
 * CK_ULONG) it must match the OID in the public key. On failure the key is NOT
 * freed here; the caller owns it. */
static int wp11_XmssImportPub(XmssKey* key, int is_xmssmt, int devId,
    const byte* pub, word32 pubLen, const byte* params, word32 paramsLen)
{
    int ret;

    ret = wc_XmssKey_Init(key, NULL, devId);
    if (ret == 0 && params != NULL) {
        CK_ULONG userOid;
        if (paramsLen != sizeof(CK_ULONG) || pubLen < WP11_XMSS_OID_LEN) {
            ret = BAD_FUNC_ARG;
        }
        else {
            XMEMCPY(&userOid, params, sizeof(userOid));
            if (userOid != (CK_ULONG)wp11_HbsReadU32(pub))
                ret = BAD_FUNC_ARG;
        }
    }
    if (ret == 0)
        ret = wc_XmssKey_ImportPubRaw_ex(key, pub, pubLen, is_xmssmt);
    return ret;
}

/* Serialize the public key: keyData holds the raw RFC 8391 public key. */
int wp11_Object_Encode_XmssKey(WP11_Object* object)
{
    int ret;
    word32 pubLen = 0;

    if (object->objClass != CKO_PUBLIC_KEY)
        return NOT_AVAILABLE_E;

    ret = wc_XmssKey_GetPubLen(object->data.xmssKey, &pubLen);
    if (ret == 0) {
        XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        object->keyData = (unsigned char*)XMALLOC(pubLen, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (object->keyData == NULL)
            ret = MEMORY_E;
    }
    if (ret == 0) {
        ret = wc_XmssKey_ExportPubRaw(object->data.xmssKey, object->keyData,
            &pubLen);
        if (ret == 0)
            object->keyDataLen = (int)pubLen;
    }
    /* On failure release the buffer so a later store does not skip re-encoding
     * (keyData != NULL) and persist an uninitialised buffer with a stale
     * length. This is public key material only, so no zeroization is needed. */
    if (ret != 0) {
        XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        object->keyData = NULL;
        object->keyDataLen = 0;
    }
    return ret;
}

int wp11_Object_Decode_XmssKey(WP11_Object* object)
{
    int ret;

    if (object->objClass != CKO_PUBLIC_KEY)
        return NOT_AVAILABLE_E;

    /* Reload from the stored raw public key; wolfSSL re-derives the parameter
     * set from the embedded OID (no separate parameter set is persisted). */
    ret = wp11_XmssImportPub(object->data.xmssKey,
        (object->type == CKK_XMSSMT) ? 1 : 0, object->devId, object->keyData,
        (word32)object->keyDataLen, NULL, 0);
    /* Object owns the key on all paths; encoded stays 0 for the single free in
     * WP11_Object_Free. See wp11_Object_Decode_HssKey. */
    object->encoded = 0;
    return ret;
}

int wp11_Object_Load_XmssKey(WP11_Object* object, int tokenId, int objId)
{
    int ret;
    void* storage = NULL;

    ret = wp11_storage_open_readonly(WOLFPKCS11_STORE_XMSSKEY_PUB, tokenId,
        objId, &storage);
    if (ret == 0) {
        ret = wp11_storage_read_alloc_array(storage, &object->keyData,
            &object->keyDataLen);
        wp11_storage_close(storage);
    }
    return ret;
}

int wp11_Object_Store_XmssKey(WP11_Object* object, int tokenId,
    int objId)
{
    int ret = 0;
    void* storage = NULL;

    if (object->keyData == NULL)
        ret = wp11_Object_Encode_XmssKey(object);
    if (ret == 0)
        ret = wp11_storage_open(WOLFPKCS11_STORE_XMSSKEY_PUB, tokenId, objId,
            object->keyDataLen, &storage);
    if (ret == 0) {
        ret = wp11_storage_write_array(storage, object->keyData,
            object->keyDataLen);
        wp11_storage_close(storage);
    }
    return ret;
}

/* Import an XMSS/XMSS^MT public key from a C_CreateObject template. data[1] is
 * the raw RFC 8391 public key; data[0] (CKA_PARAMETER_SET, the OID as a
 * CK_ULONG) is optional and, when present, is validated against the key.
 * Private-key import is rejected. */
int WP11_Object_SetXmssKey(WP11_Object* object, unsigned char** data,
                           CK_ULONG* len)
{
    int ret = 0;
    XmssKey* newKey = NULL;

    if (object == NULL || data == NULL || len == NULL)
        return BAD_FUNC_ARG;
    if (object->objClass != CKO_PUBLIC_KEY)
        return BAD_FUNC_ARG;
    /* A public key must carry its value; an absent CKA_VALUE is an
     * incomplete template (no keygen path fills it later). Reject it. */
    if (data[1] == NULL)
        return BAD_FUNC_ARG;

    if (object->onToken)
        WP11_Lock_LockRW(object->lock);

    /* Import into a temporary key and swap it in only after it validates, so a
     * failed re-import leaves the existing key unchanged (PKCS#11 requires a
     * failed C_SetAttributeValue to be a no-op). */
    newKey = (XmssKey*)XMALLOC(sizeof(XmssKey), NULL, DYNAMIC_TYPE_KEY);
    if (newKey == NULL)
        ret = MEMORY_E;
    if (ret == 0) {
        XMEMSET(newKey, 0, sizeof(XmssKey));
        ret = wp11_XmssImportPub(newKey, (object->type == CKK_XMSSMT) ? 1 : 0,
            object->devId, data[1], (word32)len[1], data[0], (word32)len[0]);
    }
    if (ret == 0) {
        /* Replace the live key and drop the cached serialization so a later
         * store re-encodes from the new key. */
        if (object->data.xmssKey != NULL) {
            if (!object->encoded)
                wc_XmssKey_Free(object->data.xmssKey);
            XFREE(object->data.xmssKey, NULL, DYNAMIC_TYPE_KEY);
        }
        object->data.xmssKey = newKey;
        object->encoded = 0;
        newKey = NULL;
        XFREE(object->keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        object->keyData = NULL;
        object->keyDataLen = 0;
    }
    if (newKey != NULL) {
        wc_XmssKey_Free(newKey);
        XFREE(newKey, NULL, DYNAMIC_TYPE_KEY);
    }

    if (object->onToken)
        WP11_Lock_UnlockRW(object->lock);
    return ret;
}

/* Verify an XMSS/XMSS^MT signature over a raw message. Stateless. */
int WP11_Xmss_Verify(unsigned char* sig, word32 sigLen, unsigned char* data,
                     word32 dataLen, int* stat, WP11_Object* pub)
{
    int ret;
    word32 expSigLen = 0;

    if (pub == NULL || pub->data.xmssKey == NULL || stat == NULL)
        return BAD_FUNC_ARG;

    /* Verification only reads the key: wc_XmssKey_Verify works from a locally
     * allocated XmssState, so a shared RO lock is safe for concurrent verifies
     * on the same token object. */
    if (pub->onToken)
        WP11_Lock_LockRO(pub->lock);

    /* A wrong-length signature cannot be valid for this key; report it as an
     * invalid signature rather than a function failure. wolfSSL's XMSS verify
     * also rejects a zero-length message with BAD_FUNC_ARG; treat that the same
     * way (an invalid verification, not an internal failure). */
    if (wc_XmssKey_GetSigLen(pub->data.xmssKey, &expSigLen) == 0 &&
            sigLen != expSigLen) {
        *stat = 0;
        ret = 0;
    }
    else if (dataLen == 0) {
        *stat = 0;
        ret = 0;
    }
    else {
        ret = wc_XmssKey_Verify(pub->data.xmssKey, sig, sigLen, data,
            (int)dataLen);
        /* Only SIG_VERIFY_E maps to stat=0; other argument/state errors
         * surface as a function failure so they are not silently reported as
         * an invalid signature. */
        if (ret == 0) {
            *stat = 1;
        }
        else if (ret == SIG_VERIFY_E) {
            *stat = 0;
            ret = 0;
        }
        else {
            *stat = 0;
        }
    }

    if (pub->onToken)
        WP11_Lock_UnlockRO(pub->lock);

    return ret;
}

/* Serve XMSS-specific attributes from a public-key object. */
int XmssObject_GetAttr(WP11_Object* object, CK_ATTRIBUTE_TYPE type,
                              byte* data, CK_ULONG* len)
{
    int ret = 0;

    if (object == NULL || object->data.xmssKey == NULL || len == NULL)
        return BAD_FUNC_ARG;

    switch (type) {
        case CKA_VALUE:
            if (object->objClass == CKO_PUBLIC_KEY) {
                word32 pubLen = 0;
                ret = wc_XmssKey_GetPubLen(object->data.xmssKey, &pubLen);
                if (ret == 0) {
                    if (data == NULL)
                        *len = pubLen;
                    else if (*len < pubLen) {
                        *len = pubLen;
                        ret = BUFFER_E;
                    }
                    else {
                        ret = wc_XmssKey_ExportPubRaw(object->data.xmssKey,
                            data, &pubLen);
                        if (ret == 0)
                            *len = pubLen;
                    }
                }
            }
            else {
                *len = CK_UNAVAILABLE_INFORMATION;
                ret = NOT_AVAILABLE_E;
            }
            break;
        case CKA_PARAMETER_SET: {
            /* The XMSS parameter set is identified by the OID in the leading
             * bytes of the raw public key; return it as a CK_ULONG. */
            CK_ULONG v;
            word32 pubLen = 0;
            byte* raw;

            if (object->objClass != CKO_PUBLIC_KEY) {
                *len = CK_UNAVAILABLE_INFORMATION;
                ret = NOT_AVAILABLE_E;
                break;
            }
            if (data == NULL) {
                *len = sizeof(v);
                break;
            }
            if (*len < sizeof(v)) {
                *len = sizeof(v);
                ret = BUFFER_E;
                break;
            }
            ret = wc_XmssKey_GetPubLen(object->data.xmssKey, &pubLen);
            if (ret == 0 && pubLen < WP11_XMSS_OID_LEN)
                ret = NOT_AVAILABLE_E;
            if (ret == 0) {
                raw = (byte*)XMALLOC(pubLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (raw == NULL) {
                    ret = MEMORY_E;
                }
                else {
                    ret = wc_XmssKey_ExportPubRaw(object->data.xmssKey, raw,
                        &pubLen);
                    if (ret == 0) {
                        v = (CK_ULONG)wp11_HbsReadU32(raw);
                        XMEMCPY(data, &v, sizeof(v));
                        *len = sizeof(v);
                    }
                    XFREE(raw, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                }
            }
            break;
        }
        default:
            ret = NOT_AVAILABLE_E;
            break;
    }
    return ret;
}
#endif /* WOLFPKCS11_XMSS */
