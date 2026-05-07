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
 *   1. Generate an HSS keypair (1 level / H=5 / W=4 → 32 sigs).
 *   2. Sign a message; record CKA_HSS_KEYS_REMAINING.
 *   3. C_Finalize and C_Initialize again.
 *   4. Find the persisted private key by label.
 *   5. Confirm CKA_HSS_KEYS_REMAINING matches the post-step-2 value.
 *   6. Sign a different message and verify both signatures.
 *   7. Confirm CKA_HSS_KEYS_REMAINING decremented by exactly one.
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
#include <string.h>

#if defined(WOLFPKCS11_LMS_PRIVATE) && !defined(WOLFPKCS11_NO_STORE)

#define CHECK_CKR(rv, msg)                                                 \
    do {                                                                   \
        if ((rv) != CKR_OK) {                                              \
            fprintf(stderr, "%s:%d - %s: 0x%lx FAIL\n",                    \
                __FILE__, __LINE__, (msg), (unsigned long)(rv));           \
        }                                                                  \
    } while (0)

#define CHECK_COND(cond, rv, msg)                                          \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "%s:%d - %s FAIL\n",                           \
                __FILE__, __LINE__, (msg));                                \
            (rv) = CKR_GENERAL_ERROR;                                      \
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

    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
        CHECK_CKR(ret, "GetSlotList");
    }
    if (ret == CKR_OK && slotCount > 0)
        slot = slotList[0];
    else if (ret == CKR_OK)
        ret = CKR_GENERAL_ERROR;
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
    if (ret == CKR_OK) {
        ret = funcList->C_Login(s, CKU_SO, soPin, soPinLen);
        CHECK_CKR(ret, "Login SO");
        if (ret == CKR_OK) {
            ret = funcList->C_InitPIN(s, userPin, userPinLen);
            CHECK_CKR(ret, "InitPIN");
        }
        funcList->C_Logout(s);
        funcList->C_CloseSession(s);
    }
    return ret;
}

static CK_RV pkcs11_open_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    ret = funcList->C_OpenSession(slot, flags, NULL, NULL, session);
    CHECK_CKR(ret, "OpenSession");
    if (ret == CKR_OK && userPinLen > 0) {
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
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, h, 1, &count);
        CHECK_CKR(ret, "FindObjects (priv)");
    }
    funcList->C_FindObjectsFinal(session);
    if (ret == CKR_OK && count != 1)
        ret = CKR_GENERAL_ERROR;
    return ret;
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
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, h, 1, &count);
        CHECK_CKR(ret, "FindObjects (pub)");
    }
    funcList->C_FindObjectsFinal(session);
    if (ret == CKR_OK && count != 1)
        ret = CKR_GENERAL_ERROR;
    return ret;
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
    if (ret == CKR_OK) {
        ret = funcList->C_Sign(session, (CK_BYTE_PTR)msg, msgLen, sig, sigLen);
        CHECK_CKR(ret, "C_Sign (HSS)");
    }
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
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, (CK_BYTE_PTR)msg, msgLen,
            (CK_BYTE_PTR)sig, sigLen);
        CHECK_CKR(ret, "C_Verify (HSS)");
    }
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
        CHECK_COND(remaining_after_first == 31, ret,
            "KEYS_REMAINING != 31 after first sign");
    }

    funcList->C_Logout(s1);
    funcList->C_CloseSession(s1);
    pkcs11_final();

    printf("Re-initializing PKCS#11 to load token from disk...\n");
    ret = pkcs11_init();
    if (ret != CKR_OK) return ret;
    if (ret == CKR_OK)
        ret = pkcs11_open_session(&s2);
    if (ret == CKR_OK) {
        ret = find_hss_priv(s2, &priv2);
        if (ret != CKR_OK) {
            fprintf(stderr, "Persisted private key not found\n");
        }
    }
    if (ret == CKR_OK)
        ret = find_hss_pub(s2, &pub2);
    if (ret == CKR_OK) {
        ret = get_keys_remaining(s2, priv2, &remaining_after_load);
        CHECK_CKR(ret, "GetAttr KEYS_REMAINING (after load)");
        printf("After reload, KEYS_REMAINING = %lu (must equal %lu)\n",
            (unsigned long)remaining_after_load,
            (unsigned long)remaining_after_first);
        CHECK_COND(remaining_after_load == remaining_after_first, ret,
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
        CHECK_COND(remaining_after_second == 30, ret,
            "KEYS_REMAINING != 30 after second sign");
    }

    /* Cleanup: destroy persisted objects so the test is repeatable. */
    if (priv2 != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(s2, priv2);
    if (pub2 != CK_INVALID_HANDLE)
        funcList->C_DestroyObject(s2, pub2);
    funcList->C_Logout(s2);
    funcList->C_CloseSession(s2);
    pkcs11_final();
    return ret;
}

#endif /* WOLFPKCS11_LMS_PRIVATE && !WOLFPKCS11_NO_STORE */

int main(int argc, char* argv[])
{
    (void)argc; (void)argv;
#if defined(WOLFPKCS11_LMS_PRIVATE) && !defined(WOLFPKCS11_NO_STORE)
    CK_RV ret;

#ifndef WOLFPKCS11_NO_ENV
    if (!XGETENV("WOLFPKCS11_TOKEN_PATH"))
        XSETENV("WOLFPKCS11_TOKEN_PATH", "./store/lms", 1);
#endif

    printf("wolfPKCS11 LMS/HSS State Persistence Test\n");
    printf("=========================================\n\n");

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
