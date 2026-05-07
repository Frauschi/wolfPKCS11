/* lms_state_persistence_test.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
 *
 * Tests for LMS/HSS state persistence across session cycles.
 *
 * Stateful one-time hash-based signatures must never re-use a leaf index.
 * This test exercises:
 *   1. Generate an HSS keypair (1 level / H=5 / W=4 = 32 sigs).
 *   2. Sign a message; record CKA_HSS_KEYS_REMAINING.
 *   3. C_Finalize and C_Initialize again.
 *   4. Find the persisted private key by label.
 *   5. Confirm CKA_HSS_KEYS_REMAINING matches the post-step-2 value.
 *   6. Sign a different message and verify both signatures.
 *   7. Confirm CKA_HSS_KEYS_REMAINING decremented by exactly one.
 *   8. Crash-injection: corrupt the on-disk state file; verify next sign
 *      after C_Initialize is refused (CKR_OBJECT_HANDLE_INVALID at find,
 *      since the AES-GCM-authenticated state cannot decrypt).
 *
 * The test directory is created with mkdtemp() so concurrent runs cannot
 * collide and so a pre-existing stale state file from an earlier failed
 * run cannot give a misleading pass.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/misc.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#ifndef WOLFPKCS11_DLL_FILENAME
    #define WOLFPKCS11_DLL_FILENAME "src/.libs/libwolfpkcs11.so"
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

#if defined(WOLFPKCS11_LMS_PRIVATE) && !defined(WOLFPKCS11_NO_STORE)

/* Test status: any CHECK_* failure latches a non-zero rv that is returned
 * to main(). Earlier the macro silently swallowed assertion failures and
 * the program could print "All tests passed!" while having printed FAIL
 * lines on stderr. */
#define CHECK_CKR(rv, msg)                                                 \
    do {                                                                   \
        if ((rv) != CKR_OK) {                                              \
            fprintf(stderr, "%s:%d - %s: 0x%lx FAIL\n",                    \
                __FILE__, __LINE__, (msg), (unsigned long)(rv));           \
            return (rv);                                                   \
        }                                                                  \
    } while (0)

#define CHECK_COND(cond, msg)                                              \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "%s:%d - %s FAIL\n",                           \
                __FILE__, __LINE__, (msg));                                \
            return CKR_GENERAL_ERROR;                                      \
        }                                                                  \
    } while (0)

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot = 0;
static const char* tokenName = "wolfpkcs11lms";
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;

static char tokenDir[256];

static CK_BBOOL ckTrue = CK_TRUE;
static CK_KEY_TYPE hssKeyType = CKK_HSS;
static CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;

static char hssKeyLabel[] = "test-hss-key";
static char hssPubLabel[] = "test-hss-pub";

static CK_RV pkcs11_init(void)
{
    CK_RV ret;
    CK_C_INITIALIZE_ARGS args;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = sizeof(slotList) / sizeof(slotList[0]);

#ifndef HAVE_PKCS11_STATIC
    CK_C_GetFunctionList func;
    dlib = dlopen(WOLFPKCS11_DLL_FILENAME, RTLD_NOW | RTLD_LOCAL);
    if (dlib == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return -1;
    }
    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) { dlclose(dlib); return -1; }
    ret = func(&funcList);
    if (ret != CKR_OK) { dlclose(dlib); return ret; }
#else
    ret = C_GetFunctionList(&funcList);
    if (ret != CKR_OK) return ret;
#endif

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    ret = funcList->C_Initialize(&args);
    CHECK_CKR(ret, "Initialize");

    ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    CHECK_CKR(ret, "GetSlotList");
    if (slotCount == 0)
        return CKR_GENERAL_ERROR;
    slot = slotList[0];
    return ret;
}

static void pkcs11_final(void)
{
    funcList->C_Finalize(NULL);
#ifndef HAVE_PKCS11_STATIC
    if (dlib) dlclose(dlib);
    dlib = NULL;
#endif
}

static CK_RV pkcs11_init_token(void)
{
    unsigned char label[32];
    CK_RV ret;

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenName, XSTRLEN(tokenName));
    ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
    CHECK_CKR(ret, "InitToken");
    return ret;
}

static CK_RV pkcs11_set_user_pin(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE s;
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    ret = funcList->C_OpenSession(slot, flags, NULL, NULL, &s);
    CHECK_CKR(ret, "OpenSession (PIN setup)");
    ret = funcList->C_Login(s, CKU_SO, soPin, soPinLen);
    if (ret == CKR_OK) {
        ret = funcList->C_InitPIN(s, userPin, userPinLen);
        CHECK_CKR(ret, "InitPIN");
    }
    funcList->C_Logout(s);
    funcList->C_CloseSession(s);
    return ret;
}

static CK_RV pkcs11_open_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    ret = funcList->C_OpenSession(slot, flags, NULL, NULL, session);
    CHECK_CKR(ret, "OpenSession");
    if (userPinLen > 0) {
        ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "Login USER");
    }
    return ret;
}

static CK_RV gen_hss_key(CK_SESSION_HANDLE session,
                         CK_OBJECT_HANDLE* pubKey,
                         CK_OBJECT_HANDLE* privKey)
{
    CK_RV ret;
    CK_MECHANISM mech;
    CK_HSS_PARAMS params;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_VERIFY, &ckTrue, sizeof(ckTrue) },
        { CKA_TOKEN,  &ckTrue, sizeof(ckTrue) },
        { CKA_LABEL,  hssPubLabel, sizeof(hssPubLabel) - 1 }
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_SIGN,  &ckTrue, sizeof(ckTrue) },
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
        { CKA_LABEL, hssKeyLabel, sizeof(hssKeyLabel) - 1 }
    };

    XMEMSET(&params, 0, sizeof(params));
    params.ulLevels = 1;
    params.lm_type[0] = CKL_LMS_SHA256_M32_H5;
    params.lm_ots_type[0] = CKL_LMOTS_SHA256_N32_W4;

    mech.mechanism = CKM_HSS_KEY_PAIR_GEN;
    mech.pParameter = &params;
    mech.ulParameterLen = sizeof(params);

    ret = funcList->C_GenerateKeyPair(session, &mech,
        pubTmpl, sizeof(pubTmpl)/sizeof(*pubTmpl),
        privTmpl, sizeof(privTmpl)/sizeof(*privTmpl), pubKey, privKey);
    CHECK_CKR(ret, "C_GenerateKeyPair (HSS)");
    return ret;
}

static CK_RV find_hss_priv(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* h)
{
    CK_RV ret;
    CK_ULONG count = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &privClass,    sizeof(privClass)    },
        { CKA_KEY_TYPE, &hssKeyType,   sizeof(hssKeyType)   },
        { CKA_LABEL,    hssKeyLabel,   sizeof(hssKeyLabel)-1}
    };
    ret = funcList->C_FindObjectsInit(session, tmpl, 3);
    CHECK_CKR(ret, "FindObjectsInit (priv)");
    ret = funcList->C_FindObjects(session, h, 1, &count);
    CHECK_CKR(ret, "FindObjects (priv)");
    funcList->C_FindObjectsFinal(session);
    if (count != 1)
        return CKR_GENERAL_ERROR;
    return CKR_OK;
}

static CK_RV find_hss_pub(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* h)
{
    CK_RV ret;
    CK_ULONG count = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &pubClass,     sizeof(pubClass)     },
        { CKA_KEY_TYPE, &hssKeyType,   sizeof(hssKeyType)   },
        { CKA_LABEL,    hssPubLabel,   sizeof(hssPubLabel)-1}
    };
    ret = funcList->C_FindObjectsInit(session, tmpl, 3);
    CHECK_CKR(ret, "FindObjectsInit (pub)");
    ret = funcList->C_FindObjects(session, h, 1, &count);
    CHECK_CKR(ret, "FindObjects (pub)");
    funcList->C_FindObjectsFinal(session);
    if (count != 1)
        return CKR_GENERAL_ERROR;
    return CKR_OK;
}

static CK_RV sign_msg(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv,
                      const byte* msg, CK_ULONG msgLen,
                      byte* sig, CK_ULONG* sigLen)
{
    CK_RV ret;
    CK_MECHANISM mech;
    mech.mechanism = CKM_HSS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
    ret = funcList->C_SignInit(session, &mech, priv);
    CHECK_CKR(ret, "C_SignInit (HSS)");
    ret = funcList->C_Sign(session, (CK_BYTE_PTR)msg, msgLen, sig, sigLen);
    CHECK_CKR(ret, "C_Sign (HSS)");
    return ret;
}

static CK_RV verify_msg(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pub,
                        const byte* msg, CK_ULONG msgLen,
                        const byte* sig, CK_ULONG sigLen)
{
    CK_RV ret;
    CK_MECHANISM mech;
    mech.mechanism = CKM_HSS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
    ret = funcList->C_VerifyInit(session, &mech, pub);
    CHECK_CKR(ret, "C_VerifyInit (HSS)");
    ret = funcList->C_Verify(session, (CK_BYTE_PTR)msg, msgLen,
        (CK_BYTE_PTR)sig, sigLen);
    CHECK_CKR(ret, "C_Verify (HSS)");
    return ret;
}

static CK_RV get_keys_remaining(CK_SESSION_HANDLE session,
                                CK_OBJECT_HANDLE priv,
                                CK_ULONG* out)
{
    CK_ATTRIBUTE q;
    q.type = CKA_HSS_KEYS_REMAINING;
    q.pValue = out;
    q.ulValueLen = sizeof(*out);
    return funcList->C_GetAttributeValue(session, priv, &q, 1);
}

/* Best-effort: corrupt every file in tokenDir whose name contains "state".
 * Used by the crash-injection scenario to verify that a tampered state
 * file fails AES-GCM authentication on reload (no usable in-memory key,
 * no leaf re-use). */
static int corrupt_state_files(void)
{
    DIR* d = opendir(tokenDir);
    struct dirent* e;
    int touched = 0;
    if (d == NULL) {
        fprintf(stderr, "opendir(%s): %s\n", tokenDir, strerror(errno));
        return -1;
    }
    while ((e = readdir(d)) != NULL) {
        if (strstr(e->d_name, "state") == NULL)
            continue;
        {
            char path[512];
            FILE* f;
            int n = snprintf(path, sizeof(path), "%s/%s", tokenDir, e->d_name);
            if (n <= 0 || n >= (int)sizeof(path))
                continue;
            f = fopen(path, "r+b");
            if (f == NULL)
                continue;
            /* Flip a byte in the AAD-bound header (offset 16 = winternitz)
             * so AES-GCM authentication fails on next decrypt. */
            if (fseek(f, 16, SEEK_SET) == 0) {
                int c = fgetc(f);
                if (c != EOF) {
                    fseek(f, 16, SEEK_SET);
                    fputc(c ^ 0xFF, f);
                    touched++;
                }
            }
            fclose(f);
        }
    }
    closedir(d);
    return touched > 0 ? 0 : -1;
}

static CK_RV lms_state_persistence_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE s1 = 0, s2 = 0;
    CK_OBJECT_HANDLE pub1 = CK_INVALID_HANDLE, priv1 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub2 = CK_INVALID_HANDLE, priv2 = CK_INVALID_HANDLE;
    static const byte msg1[] = "first sign before reinit";
    static const byte msg2[] = "second sign after reinit";
    byte sig1[8192], sig2[8192];
    CK_ULONG sig1Len = sizeof(sig1), sig2Len = sizeof(sig2);
    CK_ULONG remaining_after_first = 0, remaining_after_load = 0;
    CK_ULONG remaining_after_second = 0;

    ret = pkcs11_init();
    if (ret != CKR_OK) return ret;
    ret = pkcs11_init_token();
    if (ret == CKR_OK)
        ret = pkcs11_set_user_pin();
    if (ret == CKR_OK)
        ret = pkcs11_open_session(&s1);
    if (ret == CKR_OK) {
        printf("Generating HSS keypair (L=1, H=5, W=4)...\n");
        ret = gen_hss_key(s1, &pub1, &priv1);
    }
    if (ret == CKR_OK) {
        printf("Signing message #1...\n");
        ret = sign_msg(s1, priv1, msg1, sizeof(msg1) - 1, sig1, &sig1Len);
    }
    if (ret == CKR_OK)
        ret = verify_msg(s1, pub1, msg1, sizeof(msg1) - 1, sig1, sig1Len);
    if (ret == CKR_OK) {
        ret = get_keys_remaining(s1, priv1, &remaining_after_first);
        CHECK_CKR(ret, "GetAttr KEYS_REMAINING (1st)");
        printf("After 1st sign, KEYS_REMAINING = %lu (expected 31)\n",
            (unsigned long)remaining_after_first);
        CHECK_COND(remaining_after_first == 31,
            "KEYS_REMAINING != 31 after first sign");
    }
    if (ret != CKR_OK) {
        funcList->C_Logout(s1);
        funcList->C_CloseSession(s1);
        pkcs11_final();
        return ret;
    }

    funcList->C_Logout(s1);
    funcList->C_CloseSession(s1);
    pkcs11_final();

    printf("Re-initializing PKCS#11 to load token from disk...\n");
    ret = pkcs11_init();
    if (ret != CKR_OK) return ret;
    ret = pkcs11_open_session(&s2);
    if (ret == CKR_OK)
        ret = find_hss_priv(s2, &priv2);
    if (ret == CKR_OK)
        ret = find_hss_pub(s2, &pub2);
    if (ret == CKR_OK) {
        ret = get_keys_remaining(s2, priv2, &remaining_after_load);
        CHECK_CKR(ret, "GetAttr KEYS_REMAINING (after load)");
        printf("After reload, KEYS_REMAINING = %lu (must equal %lu)\n",
            (unsigned long)remaining_after_load,
            (unsigned long)remaining_after_first);
        CHECK_COND(remaining_after_load == remaining_after_first,
            "KEYS_REMAINING regressed after reload");
    }
    if (ret == CKR_OK) {
        printf("Signing message #2...\n");
        ret = sign_msg(s2, priv2, msg2, sizeof(msg2) - 1, sig2, &sig2Len);
    }
    if (ret == CKR_OK)
        ret = verify_msg(s2, pub2, msg2, sizeof(msg2) - 1, sig2, sig2Len);
    if (ret == CKR_OK)
        ret = verify_msg(s2, pub2, msg1, sizeof(msg1) - 1, sig1, sig1Len);
    if (ret == CKR_OK) {
        ret = get_keys_remaining(s2, priv2, &remaining_after_second);
        CHECK_CKR(ret, "GetAttr KEYS_REMAINING (2nd)");
        printf("After 2nd sign, KEYS_REMAINING = %lu (expected 30)\n",
            (unsigned long)remaining_after_second);
        CHECK_COND(remaining_after_second == 30,
            "KEYS_REMAINING != 30 after second sign");
    }
    if (ret != CKR_OK) {
        funcList->C_Logout(s2);
        funcList->C_CloseSession(s2);
        pkcs11_final();
        return ret;
    }

    /* Crash-injection scenario: corrupt the AAD-bound state header byte;
     * AES-GCM authentication MUST fail on next reload. After C_Initialize,
     * the private key is unusable (a Sign attempt must fail) and no leaf
     * index can be re-used. We don't destroy first because we want to test
     * recovery, not cleanup. */
    printf("Crash-injection: tampering with on-disk state header...\n");
    funcList->C_Logout(s2);
    funcList->C_CloseSession(s2);
    pkcs11_final();

    if (corrupt_state_files() != 0) {
        fprintf(stderr,
            "Could not locate state file under %s — test inconclusive.\n",
            tokenDir);
        return CKR_GENERAL_ERROR;
    }

    /* Re-init from the corrupted store. There are three places the corruption
     * can be detected, in increasing latency:
     *  (a) C_Initialize / C_Login: token load decodes objects, AES-GCM auth
     *      fails on the state file → DEVICE_ERROR or non-zero rv.
     *  (b) C_FindObjects: object is suppressed.
     *  (c) C_Sign: SignInit succeeds but Sign refuses (poison flag).
     * ANY of these constitutes a successful tamper-detection. The test
     * MUST fail only if a Sign produces a signature with no error. */
    {
        CK_RV initRet, sessRet;
        initRet = pkcs11_init();
        if (initRet != CKR_OK) {
            printf("Tampered state correctly rejected at C_Initialize: 0x%lx\n",
                (unsigned long)initRet);
            /* Don't call pkcs11_final on a failed init. */
            return CKR_OK;
        }
        sessRet = funcList->C_OpenSession(slot,
            CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &s2);
        if (sessRet != CKR_OK) {
            printf("Tampered state correctly rejected at OpenSession: 0x%lx\n",
                (unsigned long)sessRet);
            pkcs11_final();
            return CKR_OK;
        }
        if (userPinLen > 0) {
            CK_RV loginRet = funcList->C_Login(s2, CKU_USER, userPin, userPinLen);
            if (loginRet != CKR_OK) {
                printf("Tampered state correctly rejected at Login: 0x%lx\n",
                    (unsigned long)loginRet);
                funcList->C_CloseSession(s2);
                pkcs11_final();
                return CKR_OK;
            }
        }
        {
            CK_OBJECT_HANDLE bogus = CK_INVALID_HANDLE;
            CK_RV findRet = find_hss_priv(s2, &bogus);
            if (findRet != CKR_OK) {
                printf(
                    "Tampered state correctly rejected at find time: 0x%lx\n",
                    (unsigned long)findRet);
                funcList->C_Logout(s2);
                funcList->C_CloseSession(s2);
                pkcs11_final();
                return CKR_OK;
            }
            {
                byte sig3[8192];
                CK_ULONG sig3Len = sizeof(sig3);
                CK_RV signRet;
                CK_MECHANISM mech;
                mech.mechanism = CKM_HSS;
                mech.pParameter = NULL;
                mech.ulParameterLen = 0;
                signRet = funcList->C_SignInit(s2, &mech, bogus);
                if (signRet == CKR_OK) {
                    signRet = funcList->C_Sign(s2,
                        (CK_BYTE_PTR)msg1, sizeof(msg1) - 1, sig3, &sig3Len);
                }
                CHECK_COND(signRet != CKR_OK,
                    "Tampered state must NOT release a signature");
                printf("Tampered state correctly refused at sign: 0x%lx\n",
                    (unsigned long)signRet);
                funcList->C_DestroyObject(s2, bogus);
            }
        }
        funcList->C_Logout(s2);
        funcList->C_CloseSession(s2);
        pkcs11_final();
    }

    return CKR_OK;
}

#endif /* WOLFPKCS11_LMS_PRIVATE && !WOLFPKCS11_NO_STORE */

int main(int argc, char* argv[])
{
    (void)argc; (void)argv;
#if defined(WOLFPKCS11_LMS_PRIVATE) && !defined(WOLFPKCS11_NO_STORE)
    CK_RV ret;

    /* Always run in a fresh tmpdir so a stale state file from an aborted
     * previous run cannot give a misleading pass. The directory is left
     * in place after the test for post-mortem inspection on failure. */
#ifndef WOLFPKCS11_NO_ENV
    {
        const char* preset = getenv("WOLFPKCS11_TOKEN_PATH");
        if (preset != NULL && preset[0] != '\0') {
            int n = snprintf(tokenDir, sizeof(tokenDir), "%s", preset);
            if (n <= 0 || n >= (int)sizeof(tokenDir)) {
                fprintf(stderr, "WOLFPKCS11_TOKEN_PATH too long\n");
                return 1;
            }
            (void)mkdir(tokenDir, 0700);
        }
        else {
            char tmpl[] = "/tmp/wolfpkcs11_lms_XXXXXX";
            char* dir = mkdtemp(tmpl);
            if (dir == NULL) {
                fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
                return 1;
            }
            snprintf(tokenDir, sizeof(tokenDir), "%s", dir);
            if (setenv("WOLFPKCS11_TOKEN_PATH", tokenDir, 1) != 0) {
                fprintf(stderr, "setenv failed\n");
                return 1;
            }
        }
    }
#else
    snprintf(tokenDir, sizeof(tokenDir), "./store/lms");
    (void)mkdir(tokenDir, 0700);
#endif

    printf("wolfPKCS11 LMS/HSS State Persistence Test\n");
    printf("=========================================\n");
    printf("Token store directory: %s\n\n", tokenDir);

    ret = lms_state_persistence_test();
    if (ret == CKR_OK) {
        printf("\nAll tests passed!\n");
        return 0;
    }
    fprintf(stderr, "\nTest failed: 0x%lx\n", (unsigned long)ret);
    return 1;
#else
    printf("LMS_PRIVATE or KeyStore not compiled in!\n");
    return 77;
#endif
}
