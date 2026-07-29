/* hbs_private_test.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
 * Functional test for the sign-capable LMS/HSS build
 * (--enable-lms-private / WOLFPKCS11_LMS_PRIVATE). Exercises the paths that
 * the verify-only tests cannot reach:
 *
 *   - keygen -> sign (two-call length query) -> verify
 *   - durable state survives a C_Finalize/C_Initialize reload with no
 *     one-time-signature (OTS) index rollback
 *   - keygen template validation (CKA_TOKEN, missing/oversized attrs, bad
 *     mechanism parameter, invalid LMS/LMOTS type)
 *   - CKA_HSS_KEYS_REMAINING on a private key (size query, value, decrement,
 *     small-buffer error)
 *   - rejection of a private-key import that carries CKA_VALUE (forged OTS
 *     state injection)
 *   - key exhaustion poisons the key (subsequent C_Sign -> CKR_DEVICE_ERROR)
 *   - C_DestroyObject removes the encrypted state file
 *   - a tampered on-disk state file is detected on reload (no silent signing)
 *
 * The scheme used throughout is HSS L1 / LMS SHA256_M32_H5 / LMOTS
 * SHA256_N32_W4, i.e. a single 32-leaf tree, so exhaustion is reachable in 32
 * signatures.
 */

#ifdef HAVE_CONFIG_H
    #include <wolfpkcs11/config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/misc.h>

#ifndef WOLFPKCS11_USER_SETTINGS
    #include <wolfpkcs11/options.h>
#endif
#include <wolfpkcs11/pkcs11.h>

#ifndef HAVE_PKCS11_STATIC
#include <dlfcn.h>
#endif

#include <stdio.h>
#include <string.h>

#if defined(WOLFPKCS11_LMS_PRIVATE) && !defined(WOLFPKCS11_NO_STORE)

#ifndef _WIN32
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifndef WOLFPKCS11_DLL_FILENAME
    #ifdef __MACH__
    #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.dylib"
    #else
    #define WOLFPKCS11_DLL_FILENAME "./src/.libs/libwolfpkcs11.so"
    #endif
#endif

#define CHECK_CKR(rv, msg)                                                 \
    do {                                                                   \
        if ((rv) != CKR_OK) {                                             \
            fprintf(stderr, "\n%s:%d - %s: %lx - FAIL\n",                  \
                    __FILE__, __LINE__, msg, (unsigned long)(rv));         \
        }                                                                  \
    }                                                                      \
    while (0)

/* Assert that an operation failed with exactly the expected return code. */
#define CHECK_CKR_FAIL(rv, expected, msg)                                  \
    do {                                                                   \
        if ((rv) != (expected)) {                                         \
            fprintf(stderr, "\n%s:%d - %s: got %lx, expected %lx - FAIL\n",\
                    __FILE__, __LINE__, msg, (unsigned long)(rv),          \
                    (unsigned long)(expected));                            \
        }                                                                  \
    }                                                                      \
    while (0)

#ifndef HAVE_PKCS11_STATIC
static void* dlib;
#endif
static CK_FUNCTION_LIST* funcList;
static CK_SLOT_ID slot = 0;
static const char* tokenName = "wolfpkcs11";
static byte* soPin = (byte*)"password123456";
static int soPinLen = 14;
static byte* userPin = (byte*)"wolfpkcs11-test";
static int userPinLen = 15;
static const char* storeDir = "./store/hbs_priv";

static CK_BBOOL ckTrue = CK_TRUE;
static CK_BBOOL ckFalse = CK_FALSE;

/* Scheme under test: HSS L1 / H5 / W4 - a single 32-leaf tree. */
static CK_ULONG hssLevels = 1;
static CK_ULONG hssLmsType = CKL_LMS_SHA256_M32_H5;
static CK_ULONG hssLmotsType = CKL_LMOTS_SHA256_N32_W4;
#define HSS_H5_SIGS 32

static const CK_BYTE testMsg[] = "wolfPKCS11 HSS private-key sign test vector";
#define TEST_MSG_LEN ((CK_ULONG)(sizeof(testMsg) - 1))

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
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return CKR_GENERAL_ERROR;
    }
    func = (CK_C_GetFunctionList)dlsym(dlib, "C_GetFunctionList");
    if (func == NULL) {
        fprintf(stderr, "Failed to get function list function\n");
        dlclose(dlib);
        return CKR_GENERAL_ERROR;
    }
    ret = func(&funcList);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to get function list: %lx\n",
            (unsigned long)ret);
        dlclose(dlib);
        return ret;
    }
#else
    ret = C_GetFunctionList(&funcList);
    if (ret != CKR_OK) {
        fprintf(stderr, "Failed to get function list: %lx\n",
            (unsigned long)ret);
        return ret;
    }
#endif

    XMEMSET(&args, 0, sizeof(args));
    args.flags = CKF_OS_LOCKING_OK;
    ret = funcList->C_Initialize(&args);
    CHECK_CKR(ret, "Initialize");

    if (ret == CKR_OK) {
        ret = funcList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
        CHECK_CKR(ret, "Get Slot List");
    }
    if (ret == CKR_OK) {
        if (slotCount > 0)
            slot = slotList[0];
        else {
            fprintf(stderr, "No slots available\n");
            ret = CKR_GENERAL_ERROR;
        }
    }
    return ret;
}

static void pkcs11_final(void)
{
    funcList->C_Finalize(NULL);
#ifndef HAVE_PKCS11_STATIC
    if (dlib != NULL) {
        dlclose(dlib);
        dlib = NULL;
    }
#endif
}

static CK_RV pkcs11_init_token(void)
{
    CK_RV ret;
    unsigned char label[32];

    XMEMSET(label, ' ', sizeof(label));
    XMEMCPY(label, tokenName, strlen(tokenName));
    ret = funcList->C_InitToken(slot, soPin, soPinLen, label);
    CHECK_CKR(ret, "Init Token");
    return ret;
}

static CK_RV pkcs11_set_user_pin(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session;
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = funcList->C_OpenSession(slot, flags, NULL, NULL, &session);
    CHECK_CKR(ret, "Open Session for PIN setup");
    if (ret == CKR_OK) {
        ret = funcList->C_Login(session, CKU_SO, soPin, soPinLen);
        CHECK_CKR(ret, "Login as SO");
        if (ret == CKR_OK) {
            ret = funcList->C_InitPIN(session, userPin, userPinLen);
            CHECK_CKR(ret, "Init User PIN");
        }
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    return ret;
}

static CK_RV pkcs11_open_session(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = funcList->C_OpenSession(slot, flags, NULL, NULL, session);
    CHECK_CKR(ret, "Open Session");
    if (ret == CKR_OK) {
        ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
        CHECK_CKR(ret, "Login");
    }
    return ret;
}

static void close_session(CK_SESSION_HANDLE session)
{
    if (session != CK_INVALID_HANDLE) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
}

/* Remove every wp11_* store artifact so each test starts from a clean token. */
static void cleanup_store(void)
{
#ifndef _WIN32
    DIR* d;
    struct dirent* e;
    char path[512];

    d = opendir(storeDir);
    if (d == NULL)
        return;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "wp11_", 5) == 0) {
            snprintf(path, sizeof(path), "%s/%s", storeDir, e->d_name);
            (void)remove(path);
        }
    }
    closedir(d);
#endif
}

/* Fresh library + token + user PIN + logged-in R/W session. */
static CK_RV fresh_token(CK_SESSION_HANDLE* session)
{
    CK_RV ret;

    cleanup_store();
    ret = pkcs11_init();
    if (ret == CKR_OK)
        ret = pkcs11_init_token();
    if (ret == CKR_OK)
        ret = pkcs11_set_user_pin();
    if (ret == CKR_OK)
        ret = pkcs11_open_session(session);
    return ret;
}

/* Re-open the existing on-disk token (reload path) without wiping the store. */
static CK_RV reopen_token(CK_SESSION_HANDLE* session)
{
    CK_RV ret;

    ret = pkcs11_init();
    if (ret == CKR_OK)
        ret = pkcs11_open_session(session);
    return ret;
}

/* Like reopen_token but does not log a login failure as a FAIL: a tampered
 * token is expected to fail the login-time reload, so the caller inspects the
 * return code instead of treating it as an error. */
static CK_RV reopen_token_quiet(CK_SESSION_HANDLE* session)
{
    CK_RV ret;
    int flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    ret = pkcs11_init();
    if (ret == CKR_OK)
        ret = funcList->C_OpenSession(slot, flags, NULL, NULL, session);
    if (ret == CKR_OK)
        ret = funcList->C_Login(*session, CKU_USER, userPin, userPinLen);
    return ret;
}

/* Generate a token-resident HSS keypair with the given scheme parameters. */
static CK_RV gen_hss_key(CK_SESSION_HANDLE session, CK_ULONG levels,
    CK_ULONG lmsType, CK_ULONG lmotsType, CK_BYTE* id, CK_ULONG idLen,
    CK_OBJECT_HANDLE* pub, CK_OBJECT_HANDLE* priv)
{
    CK_RV ret;
    CK_MECHANISM mech;
    CK_ATTRIBUTE pubTmpl[] = {
        { CKA_TOKEN,          &ckTrue,     sizeof(ckTrue)     },
        { CKA_VERIFY,         &ckTrue,     sizeof(ckTrue)     },
        { CKA_ID,             id,          idLen              },
        { CKA_HSS_LEVELS,     &levels,     sizeof(levels)     },
        { CKA_HSS_LMS_TYPE,   &lmsType,    sizeof(lmsType)    },
        { CKA_HSS_LMOTS_TYPE, &lmotsType,  sizeof(lmotsType)  },
    };
    CK_ATTRIBUTE privTmpl[] = {
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
        { CKA_SIGN,  &ckTrue, sizeof(ckTrue) },
        { CKA_ID,    id,      idLen          },
    };

    mech.mechanism = CKM_HSS_KEY_PAIR_GEN;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    ret = funcList->C_GenerateKeyPair(session, &mech,
        pubTmpl, sizeof(pubTmpl) / sizeof(*pubTmpl),
        privTmpl, sizeof(privTmpl) / sizeof(*privTmpl), pub, priv);
    return ret;
}

/* Find a single token object of the given class by CKA_ID, without reporting
 * a miss. Tests that expect the object to be gone use this so a passing run
 * never writes "FAIL" into test-suite.log. */
static CK_RV find_by_id_quiet(CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls,
    CK_BYTE* id, CK_ULONG idLen, CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ULONG count = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_ID,    id,   idLen       },
    };

    ret = funcList->C_FindObjectsInit(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl));
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, obj, 1, &count);
        funcList->C_FindObjectsFinal(session);
    }
    if (ret == CKR_OK && count != 1)
        ret = CKR_GENERAL_ERROR;
    return ret;
}

/* Find a single token object of the given class by CKA_ID. Reports a miss,
 * so only use it where the object is expected to be present. */
static CK_RV find_by_id(CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls,
    CK_BYTE* id, CK_ULONG idLen, CK_OBJECT_HANDLE* obj)
{
    CK_RV ret = find_by_id_quiet(session, cls, id, idLen, obj);

    if (ret != CKR_OK)
        fprintf(stderr, "\nExpected 1 object with the given CKA_ID - FAIL\n");
    return ret;
}

/* Sign testMsg with the two-call length-query protocol; caller frees *sigOut. */
static CK_RV hss_sign(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv,
    CK_BYTE** sigOut, CK_ULONG* sigLenOut)
{
    CK_RV ret;
    CK_MECHANISM mech;
    CK_ULONG sigLen = 0;
    CK_BYTE* sig = NULL;

    mech.mechanism = CKM_HSS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    ret = funcList->C_SignInit(session, &mech, priv);
    if (ret == CKR_OK) {
        /* First call: NULL buffer -> length query, operation stays active. */
        ret = funcList->C_Sign(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, NULL,
            &sigLen);
    }
    if (ret == CKR_OK && sigLen == 0)
        ret = CKR_GENERAL_ERROR;
    if (ret == CKR_OK) {
        sig = (CK_BYTE*)XMALLOC(sigLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL)
            ret = CKR_HOST_MEMORY;
    }
    if (ret == CKR_OK)
        ret = funcList->C_Sign(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, sig,
            &sigLen);
    if (ret == CKR_OK) {
        *sigOut = sig;
        *sigLenOut = sigLen;
    }
    else if (sig != NULL) {
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}

static CK_RV hss_verify(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pub,
    CK_BYTE* sig, CK_ULONG sigLen)
{
    CK_RV ret;
    CK_MECHANISM mech;

    mech.mechanism = CKM_HSS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    ret = funcList->C_VerifyInit(session, &mech, pub);
    if (ret == CKR_OK)
        ret = funcList->C_Verify(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, sig,
            sigLen);
    return ret;
}

static CK_RV get_keys_remaining(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE priv, CK_ULONG* remaining)
{
    CK_ATTRIBUTE a;

    a.type = CKA_HSS_KEYS_REMAINING;
    a.pValue = remaining;
    a.ulValueLen = sizeof(*remaining);
    return funcList->C_GetAttributeValue(session, priv, &a, 1);
}

/* ---- HIGH-1: keygen -> sign (two-call) -> verify ---- */
static CK_RV test_keygen_sign_verify(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-ksv";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;

    printf("  keygen -> sign -> verify...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "C_GenerateKeyPair(CKM_HSS_KEY_PAIR_GEN)");
    }
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "C_Sign(CKM_HSS)");
    }
    if (ret == CKR_OK) {
        ret = hss_verify(session, pub, sig, sigLen);
        CHECK_CKR(ret, "C_Verify(CKM_HSS) of generated signature");
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* ---- HIGH-2: durable state survives reload with no OTS index rollback ---- */
static CK_RV test_reload_no_rollback(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-reload";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    CK_ULONG remainingBefore = 0, remainingAfterReload = 0, remainingFinal = 0;
    int i;

    printf("  sign N, reload, confirm no rollback...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "C_GenerateKeyPair");
    }
    /* Sign three times before the reload. */
    for (i = 0; ret == CKR_OK && i < 3; i++) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "pre-reload C_Sign");
        if (ret == CKR_OK) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    if (ret == CKR_OK) {
        ret = get_keys_remaining(session, priv, &remainingBefore);
        CHECK_CKR(ret, "keys-remaining before reload");
    }
    /* Force a reload from disk. */
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK) {
        printf("    --- reloading token from disk ---\n");
        ret = reopen_token(&session);
    }
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1, &pub);
    if (ret == CKR_OK) {
        ret = get_keys_remaining(session, priv, &remainingAfterReload);
        CHECK_CKR(ret, "keys-remaining after reload");
    }
    /* The counter must not have rolled back across the reload. */
    if (ret == CKR_OK && remainingAfterReload != remainingBefore) {
        fprintf(stderr, "\nOTS index rolled back on reload: before=%lu "
            "after=%lu - FAIL\n", (unsigned long)remainingBefore,
            (unsigned long)remainingAfterReload);
        ret = CKR_GENERAL_ERROR;
    }
    /* A post-reload signature must continue decrementing and still verify. */
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "post-reload C_Sign");
    }
    if (ret == CKR_OK) {
        ret = hss_verify(session, pub, sig, sigLen);
        CHECK_CKR(ret, "post-reload C_Verify");
    }
    if (ret == CKR_OK) {
        ret = get_keys_remaining(session, priv, &remainingFinal);
        CHECK_CKR(ret, "keys-remaining after post-reload sign");
    }
    if (ret == CKR_OK && remainingFinal != remainingAfterReload - 1) {
        fprintf(stderr, "\nCounter did not advance after reload: %lu -> %lu "
            "- FAIL\n", (unsigned long)remainingAfterReload,
            (unsigned long)remainingFinal);
        ret = CKR_GENERAL_ERROR;
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* ---- HIGH-3: keygen template validation ---- */
static CK_RV gen_expect(CK_SESSION_HANDLE session, CK_ATTRIBUTE* pubTmpl,
    CK_ULONG pubCount, CK_ATTRIBUTE* privTmpl, CK_ULONG privCount,
    CK_VOID_PTR param, CK_ULONG paramLen, CK_RV expected, const char* msg)
{
    CK_RV ret;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;

    mech.mechanism = CKM_HSS_KEY_PAIR_GEN;
    mech.pParameter = param;
    mech.ulParameterLen = paramLen;

    ret = funcList->C_GenerateKeyPair(session, &mech, pubTmpl, pubCount,
        privTmpl, privCount, &pub, &priv);
    CHECK_CKR_FAIL(ret, expected, msg);
    if (ret == CKR_OK) {
        /* Should not have succeeded; clean up so the test stays isolated. */
        funcList->C_DestroyObject(session, pub);
        funcList->C_DestroyObject(session, priv);
        return CKR_GENERAL_ERROR;
    }
    return (ret == expected) ? CKR_OK : ret;
}

static CK_RV test_keygen_negative_templates(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_ULONG dummyParam = 0;
    CK_ULONG badType = 0x00000099UL;
    CK_ULONG shortLevels = 1;
    CK_BYTE id[] = "hss-neg";

    /* Fully valid templates, mutated per-case below. */
    CK_ATTRIBUTE pubOk[] = {
        { CKA_TOKEN,          &ckTrue,       sizeof(ckTrue)       },
        { CKA_HSS_LEVELS,     &hssLevels,    sizeof(hssLevels)    },
        { CKA_HSS_LMS_TYPE,   &hssLmsType,   sizeof(hssLmsType)   },
        { CKA_HSS_LMOTS_TYPE, &hssLmotsType, sizeof(hssLmotsType) },
    };
    CK_ATTRIBUTE privOk[] = {
        { CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
        { CKA_ID,    id,      sizeof(id) - 1 },
    };
    /* CKA_TOKEN=FALSE on the private arm. */
    CK_ATTRIBUTE privTokFalse[] = {
        { CKA_TOKEN, &ckFalse, sizeof(ckFalse) },
        { CKA_ID,    id,       sizeof(id) - 1  },
    };
    /* Missing CKA_HSS_LMS_TYPE / LMOTS_TYPE. */
    CK_ATTRIBUTE pubIncomplete[] = {
        { CKA_TOKEN,      &ckTrue,    sizeof(ckTrue)    },
        { CKA_HSS_LEVELS, &hssLevels, sizeof(hssLevels) },
    };
    /* Wrong-sized CKA_HSS_LEVELS. */
    CK_ATTRIBUTE pubBadSize[] = {
        { CKA_TOKEN,          &ckTrue,       sizeof(ckTrue)       },
        { CKA_HSS_LEVELS,     &shortLevels,  1                    },
        { CKA_HSS_LMS_TYPE,   &hssLmsType,   sizeof(hssLmsType)   },
        { CKA_HSS_LMOTS_TYPE, &hssLmotsType, sizeof(hssLmotsType) },
    };
    /* Invalid LMS type value. */
    CK_ATTRIBUTE pubBadType[] = {
        { CKA_TOKEN,          &ckTrue,       sizeof(ckTrue)       },
        { CKA_HSS_LEVELS,     &hssLevels,    sizeof(hssLevels)    },
        { CKA_HSS_LMS_TYPE,   &badType,      sizeof(badType)      },
        { CKA_HSS_LMOTS_TYPE, &hssLmotsType, sizeof(hssLmotsType) },
    };

    printf("  keygen template validation...\n");
    ret = fresh_token(&session);

    /* Non-NULL mechanism parameter -> CKR_MECHANISM_PARAM_INVALID. */
    if (ret == CKR_OK) {
        ret = gen_expect(session, pubOk, 4, privOk, 2, &dummyParam,
            sizeof(dummyParam), CKR_MECHANISM_PARAM_INVALID,
            "non-NULL mechanism parameter");
    }
    /* CKA_TOKEN=FALSE -> CKR_TEMPLATE_INCONSISTENT. */
    if (ret == CKR_OK) {
        ret = gen_expect(session, pubOk, 4, privTokFalse, 2, NULL, 0,
            CKR_TEMPLATE_INCONSISTENT, "CKA_TOKEN=FALSE on private key");
    }
    /* Missing scheme attributes -> CKR_TEMPLATE_INCOMPLETE. */
    if (ret == CKR_OK) {
        ret = gen_expect(session, pubIncomplete, 2, privOk, 2, NULL, 0,
            CKR_TEMPLATE_INCOMPLETE, "missing CKA_HSS_LMS/LMOTS_TYPE");
    }
    /* Wrong-sized attribute -> CKR_ATTRIBUTE_VALUE_INVALID. */
    if (ret == CKR_OK) {
        ret = gen_expect(session, pubBadSize, 4, privOk, 2, NULL, 0,
            CKR_ATTRIBUTE_VALUE_INVALID, "wrong-sized CKA_HSS_LEVELS");
    }
    /* Invalid LMS type -> CKR_MECHANISM_PARAM_INVALID. */
    if (ret == CKR_OK) {
        ret = gen_expect(session, pubBadType, 4, privOk, 2, NULL, 0,
            CKR_MECHANISM_PARAM_INVALID, "invalid CKA_HSS_LMS_TYPE");
    }

    close_session(session);
    pkcs11_final();
    return ret;
}

/* ---- MEDIUM-8: CKA_HSS_KEYS_REMAINING on a private key ---- */
static CK_RV test_keys_remaining_private(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-remain";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    CK_ULONG remaining = 0, remainingAfter = 0;
    CK_ATTRIBUTE a;
    CK_BYTE small = 0;

    printf("  CKA_HSS_KEYS_REMAINING on private key...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "C_GenerateKeyPair");
    }
    /* Size query: NULL buffer must report sizeof(CK_ULONG). */
    if (ret == CKR_OK) {
        a.type = CKA_HSS_KEYS_REMAINING;
        a.pValue = NULL;
        a.ulValueLen = 0;
        ret = funcList->C_GetAttributeValue(session, priv, &a, 1);
        CHECK_CKR(ret, "keys-remaining size query");
        if (ret == CKR_OK && a.ulValueLen != sizeof(CK_ULONG)) {
            fprintf(stderr, "\nkeys-remaining size query returned %lu - FAIL\n",
                (unsigned long)a.ulValueLen);
            ret = CKR_GENERAL_ERROR;
        }
    }
    /* Value must equal the full 2^(levels*height) tree size before signing. */
    if (ret == CKR_OK) {
        ret = get_keys_remaining(session, priv, &remaining);
        CHECK_CKR(ret, "keys-remaining value");
    }
    if (ret == CKR_OK && remaining != HSS_H5_SIGS) {
        fprintf(stderr, "\nInitial keys-remaining %lu, expected %d - FAIL\n",
            (unsigned long)remaining, HSS_H5_SIGS);
        ret = CKR_GENERAL_ERROR;
    }
    /* Too-small buffer must be reported as CKR_BUFFER_TOO_SMALL. */
    if (ret == CKR_OK) {
        a.type = CKA_HSS_KEYS_REMAINING;
        a.pValue = &small;
        a.ulValueLen = sizeof(small);
        ret = funcList->C_GetAttributeValue(session, priv, &a, 1);
        CHECK_CKR_FAIL(ret, CKR_BUFFER_TOO_SMALL, "keys-remaining small buffer");
        ret = (ret == CKR_BUFFER_TOO_SMALL) ? CKR_OK : CKR_GENERAL_ERROR;
    }
    /* The count decrements by one after a signature. */
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "C_Sign");
    }
    if (ret == CKR_OK) {
        ret = get_keys_remaining(session, priv, &remainingAfter);
        CHECK_CKR(ret, "keys-remaining after sign");
    }
    if (ret == CKR_OK && remainingAfter != remaining - 1) {
        fprintf(stderr, "\nkeys-remaining did not decrement: %lu -> %lu "
            "- FAIL\n", (unsigned long)remaining, (unsigned long)remainingAfter);
        ret = CKR_GENERAL_ERROR;
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* ---- MEDIUM-9: private-key import carrying CKA_VALUE is rejected ---- */
static CK_RV test_import_value_rejected(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_HSS;
    CK_BYTE fakeValue[64];
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,          &privClass,    sizeof(privClass)    },
        { CKA_KEY_TYPE,       &keyType,      sizeof(keyType)      },
        { CKA_TOKEN,          &ckTrue,       sizeof(ckTrue)       },
        { CKA_SIGN,           &ckTrue,       sizeof(ckTrue)       },
        { CKA_HSS_LEVELS,     &hssLevels,    sizeof(hssLevels)    },
        { CKA_HSS_LMS_TYPE,   &hssLmsType,   sizeof(hssLmsType)   },
        { CKA_HSS_LMOTS_TYPE, &hssLmotsType, sizeof(hssLmotsType) },
        { CKA_VALUE,          fakeValue,     sizeof(fakeValue)    },
    };

    printf("  private-key import with CKA_VALUE is rejected...\n");
    XMEMSET(fakeValue, 0xAB, sizeof(fakeValue));
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        CK_RV cret = funcList->C_CreateObject(session, tmpl,
            sizeof(tmpl) / sizeof(*tmpl), &obj);
        if (cret == CKR_OK) {
            fprintf(stderr, "\nValue-carrying HSS private-key import accepted "
                "- FAIL\n");
            funcList->C_DestroyObject(session, obj);
            ret = CKR_GENERAL_ERROR;
        }
        else {
            printf("    rejected with %lx (expected)\n", (unsigned long)cret);
        }
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* ---- MEDIUM-7: exhaustion poisons the key -> CKR_DEVICE_ERROR ---- */
static CK_RV test_exhaustion_poison(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-exhaust";
    CK_MECHANISM mech;
    CK_BYTE sig[4096];
    CK_ULONG sigLen;
    CK_ULONG initialRemaining = 0;
    int successes = 0;
    int i;

    mech.mechanism = CKM_HSS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    printf("  key exhaustion poisons the key...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "C_GenerateKeyPair");
    }
    if (ret == CKR_OK) {
        ret = get_keys_remaining(session, priv, &initialRemaining);
        CHECK_CKR(ret, "initial keys-remaining");
    }
    /* Sign until the tree is exhausted. Each failed C_Sign must have cleared
     * the operation (MEDIUM-4), so the next C_SignInit succeeds. */
    for (i = 0; ret == CKR_OK && i < HSS_H5_SIGS + 4; i++) {
        CK_RV sret = funcList->C_SignInit(session, &mech, priv);
        if (sret != CKR_OK) {
            fprintf(stderr, "\nC_SignInit failed at iter %d: %lx - FAIL\n",
                i, (unsigned long)sret);
            ret = CKR_GENERAL_ERROR;
            break;
        }
        sigLen = sizeof(sig);
        sret = funcList->C_Sign(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, sig,
            &sigLen);
        if (sret == CKR_OK) {
            successes++;
        }
        else {
            /* First failure: the tree is spent. The very next attempt must be
             * reported as a poisoned key (CKR_DEVICE_ERROR). */
            printf("    exhausted after %d signatures (first failure %lx)\n",
                successes, (unsigned long)sret);
            sret = funcList->C_SignInit(session, &mech, priv);
            CHECK_CKR(sret, "C_SignInit after exhaustion");
            if (sret == CKR_OK) {
                sigLen = sizeof(sig);
                sret = funcList->C_Sign(session, (CK_BYTE*)testMsg,
                    TEST_MSG_LEN, sig, &sigLen);
                CHECK_CKR_FAIL(sret, CKR_DEVICE_ERROR,
                    "poisoned-key C_Sign");
                if (sret != CKR_DEVICE_ERROR)
                    ret = CKR_GENERAL_ERROR;
            }
            else {
                ret = CKR_GENERAL_ERROR;
            }
            break;
        }
    }
    if (ret == CKR_OK && successes != (int)initialRemaining) {
        fprintf(stderr, "\nSigned %d times, keys-remaining said %lu - FAIL\n",
            successes, (unsigned long)initialRemaining);
        ret = CKR_GENERAL_ERROR;
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

#ifndef _WIN32
/* Locate the single encrypted HSS state file in the store directory. */
static CK_RV find_state_file(char* path, size_t pathLen)
{
    DIR* d;
    struct dirent* e;
    CK_RV ret = CKR_OBJECT_HANDLE_INVALID;
    const char* prefix = "wp11_hsskey_priv_state_";

    d = opendir(storeDir);
    if (d == NULL)
        return CKR_GENERAL_ERROR;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, prefix, strlen(prefix)) == 0) {
            snprintf(path, pathLen, "%s/%s", storeDir, e->d_name);
            ret = CKR_OK;
            break;
        }
    }
    closedir(d);
    return ret;
}

/* ---- MEDIUM-10: C_DestroyObject removes the encrypted state file ---- */
static CK_RV test_destroy_removes_state(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-destroy";
    char statePath[512];
    FILE* f;

    printf("  C_DestroyObject removes the state file...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "C_GenerateKeyPair");
    }
    if (ret == CKR_OK) {
        ret = find_state_file(statePath, sizeof(statePath));
        CHECK_CKR(ret, "locate state file after keygen");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, priv);
        CHECK_CKR(ret, "C_DestroyObject(private key)");
    }
    if (ret == CKR_OK) {
        f = fopen(statePath, "rb");
        if (f != NULL) {
            fclose(f);
            fprintf(stderr, "\nState file still present after destroy: %s "
                "- FAIL\n", statePath);
            ret = CKR_GENERAL_ERROR;
        }
        else {
            printf("    state file removed\n");
        }
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* ---- MEDIUM-11: a tampered on-disk state file is detected on reload ---- */
static CK_RV test_state_tamper_detected(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-tamper";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    char statePath[512];
    FILE* f;
    long fsize;
    int flipByte;

    printf("  tampered state file is detected on reload...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "C_GenerateKeyPair");
    }
    /* Sign once so a real advanced state is on disk before we tamper it. */
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "C_Sign before tamper");
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    if (ret == CKR_OK)
        ret = find_state_file(statePath, sizeof(statePath));
    /* Force everything to disk, then flip a ciphertext byte near the end. */
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK) {
        f = fopen(statePath, "rb+");
        if (f == NULL)
            ret = CKR_GENERAL_ERROR;
        else {
            CK_BYTE b = 0;
            fseek(f, 0, SEEK_END);
            fsize = ftell(f);
            flipByte = (int)(fsize > 4 ? fsize - 4 : 0);
            fseek(f, flipByte, SEEK_SET);
            if (fread(&b, 1, 1, f) == 1) {
                b ^= 0xFF;
                fseek(f, flipByte, SEEK_SET);
                fwrite(&b, 1, 1, f);
            }
            else {
                ret = CKR_GENERAL_ERROR;
            }
            fclose(f);
        }
    }
    /* Reload and attempt to use the key. The AES-GCM authentication failure
     * must surface as an error and never produce a signature from
     * unauthenticated state. Detection may happen at C_Login (the reload runs
     * during login-time decode) or, if login proceeds, at C_Sign. Either is a
     * safe outcome; only a produced signature is a failure. */
    if (ret == CKR_OK) {
        CK_RV rret;

        printf("    --- reloading tampered token ---\n");
        rret = reopen_token_quiet(&session);
        if (rret != CKR_OK) {
            printf("    tamper detected at login: %lx\n",
                (unsigned long)rret);
        }
        else if (find_by_id_quiet(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1,
                     &priv) != CKR_OK) {
            printf("    tampered key not usable after login\n");
        }
        else {
            CK_RV sret = hss_sign(session, priv, &sig, &sigLen);
            if (sret == CKR_OK) {
                fprintf(stderr, "\nSigned with tampered state - FAIL\n");
                if (sig != NULL)
                    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                ret = CKR_GENERAL_ERROR;
            }
            else {
                printf("    signing correctly refused: %lx\n",
                    (unsigned long)sret);
            }
        }
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* ---- Phase 3: state-write failure poisons the key; reload never advances
 * past the last durable index. ---- */
static CK_RV test_write_failure_poison(void)
{
    CK_RV ret, sret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-wfail";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0, before = 0, after = 0;
    struct stat dirStat;
    int dirModeSaved = 0;
    int skipInjection = 0;

    printf("  state-write failure poisons the key...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    /* One good signature establishes a durable baseline index on disk. */
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "baseline sign");
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &before);
    /* Make the store directory unwritable so the durable state write fails.
     * Root bypasses DAC permission checks, so the write would still succeed
     * and the assertion below would fail for a reason that says nothing about
     * the code under test. */
    if (ret == CKR_OK && geteuid() == 0) {
        printf("    skipping write-failure injection (running as root)\n");
        skipInjection = 1;
    }
    if (ret == CKR_OK && !skipInjection) {
        /* Capture the real mode so it can be put back exactly. */
        if (stat(storeDir, &dirStat) != 0 || chmod(storeDir, 0500) != 0)
            ret = CKR_GENERAL_ERROR;
        else
            dirModeSaved = 1;
    }
    if (ret == CKR_OK && !skipInjection) {
        sret = hss_sign(session, priv, &sig, &sigLen);
        if (sret == CKR_OK) {
            fprintf(stderr, "\nsigned despite an unwritable store - FAIL\n");
            if (sig != NULL) {
                XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                sig = NULL;
            }
            ret = CKR_GENERAL_ERROR;
        }
        else {
            printf("    write-failed sign refused: %lx\n", (unsigned long)sret);
        }
    }
    if (dirModeSaved)
        (void)chmod(storeDir, dirStat.st_mode);   /* restore, even on failure */
    if (skipInjection)
        return ret;
    /* The key is poisoned until reloaded: the next sign is CKR_DEVICE_ERROR. */
    if (ret == CKR_OK) {
        sret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR_FAIL(sret, CKR_DEVICE_ERROR, "poisoned-key sign");
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
        if (sret != CKR_DEVICE_ERROR)
            ret = CKR_GENERAL_ERROR;
    }
    /* Reload must recover to the last durable index - the failed write must not
     * have advanced it. */
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1, &pub);
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &after);
    if (ret == CKR_OK && after != before) {
        fprintf(stderr, "\nreload advanced past a failed write: %lu -> %lu "
            "- FAIL\n", (unsigned long)before, (unsigned long)after);
        ret = CKR_GENERAL_ERROR;
    }
    /* And it still signs correctly from the recovered state. */
    if (ret == CKR_OK)
        ret = hss_sign(session, priv, &sig, &sigLen);
    if (ret == CKR_OK)
        ret = hss_verify(session, pub, sig, sigLen);
    CHECK_CKR(ret, "post-recovery sign/verify");
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* ---- Phase 3: per-sign durability survives an unclean exit. A forked child
 * signs and _exit()s with NO C_Finalize; the parent confirms the state advanced
 * durably and the consumed index is never reused. ---- */
static CK_RV test_crash_durability(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-crash";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0, before = 0, after = 0;
    pid_t pid;
    int status = 0;

    printf("  per-sign durability survives an unclean exit (fork)...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &before);
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret != CKR_OK)
        return ret;

    pid = fork();
    if (pid == 0) {
        /* Child: fresh process. Reload, sign once (durable), then hard-exit
         * with no C_Finalize, simulating a crash right after a signature. */
        CK_SESSION_HANDLE cs = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE cp = CK_INVALID_HANDLE;
        CK_BYTE* csig = NULL;
        CK_ULONG cslen = 0;
        CK_RV cret;

        cret = reopen_token(&cs);
        if (cret == CKR_OK)
            cret = find_by_id(cs, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &cp);
        if (cret == CKR_OK)
            cret = hss_sign(cs, cp, &csig, &cslen);
        _exit(cret == CKR_OK ? 0 : 1);
    }
    if (pid < 0)
        return CKR_GENERAL_ERROR;
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0) {
        fprintf(stderr, "\nchild sign failed (status %d) - FAIL\n", status);
        return CKR_GENERAL_ERROR;
    }

    /* Parent: the child's signature must have durably advanced the state even
     * though it never finalized, and the recovered index is exactly one past
     * the parent's - never reused. */
    ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1, &pub);
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &after);
    if (ret == CKR_OK && after != before - 1) {
        fprintf(stderr, "\ncrash durability: remaining %lu -> %lu, expected a "
            "drop of 1 - FAIL\n", (unsigned long)before, (unsigned long)after);
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = hss_sign(session, priv, &sig, &sigLen);
    if (ret == CKR_OK)
        ret = hss_verify(session, pub, sig, sigLen);
    CHECK_CKR(ret, "post-crash sign/verify");
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* ---- Phase 3: on-disk state-file corruption matrix. ---- */
#define CORRUPT_TRUNCATE 0
#define CORRUPT_MAGIC    1
#define CORRUPT_PARAM    2
#define CORRUPT_TAG      3

static CK_RV corrupt_state_and_check(const char* label, int type)
{
    CK_RV ret, sret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-corrupt";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    char statePath[512];
    FILE* f;
    long fsize = 0, off;
    CK_BYTE b = 0;

    printf("    [%s]...\n", label);
    ret = fresh_token(&session);
    if (ret == CKR_OK)
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    if (ret == CKR_OK)
        ret = find_state_file(statePath, sizeof(statePath));
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret != CKR_OK)
        return ret;

    if (type == CORRUPT_TRUNCATE) {
        f = fopen(statePath, "rb");
        if (f == NULL)
            return CKR_GENERAL_ERROR;
        fseek(f, 0, SEEK_END);
        fsize = ftell(f);
        fclose(f);
        if (truncate(statePath, fsize > 8 ? fsize - 8 : 0) != 0)
            return CKR_GENERAL_ERROR;
    }
    else {
        f = fopen(statePath, "rb+");
        if (f == NULL)
            return CKR_GENERAL_ERROR;
        fseek(f, 0, SEEK_END);
        fsize = ftell(f);
        if (type == CORRUPT_MAGIC)
            off = 0;                 /* header magic */
        else if (type == CORRUPT_PARAM)
            off = 12;                /* scheme-param bytes (AAD-bound) */
        else
            off = fsize - 1;         /* CORRUPT_TAG: last GCM tag byte */
        fseek(f, off, SEEK_SET);
        if (fread(&b, 1, 1, f) == 1) {
            b ^= 0xFF;
            fseek(f, off, SEEK_SET);
            fwrite(&b, 1, 1, f);
        }
        else {
            fclose(f);
            return CKR_GENERAL_ERROR;
        }
        fclose(f);
    }

    /* Reload and attempt to use the key: it must be refused - detection may
     * surface at login-time reload or at C_Sign - never a produced signature. */
    ret = reopen_token_quiet(&session);
    if (ret != CKR_OK) {
        printf("      detected at login: %lx\n", (unsigned long)ret);
        ret = CKR_OK;
    }
    else if (find_by_id_quiet(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1,
                 &priv)
                 != CKR_OK) {
        printf("      key not usable after corruption\n");
    }
    else {
        sret = hss_sign(session, priv, &sig, &sigLen);
        if (sret == CKR_OK) {
            fprintf(stderr, "\n[%s] signed with corrupted state - FAIL\n",
                label);
            if (sig != NULL)
                XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            ret = CKR_GENERAL_ERROR;
        }
        else {
            printf("      signing refused: %lx\n", (unsigned long)sret);
        }
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

static CK_RV test_corruption_matrix(void)
{
    CK_RV ret;

    printf("  on-disk state corruption matrix...\n");
    ret = corrupt_state_and_check("truncated", CORRUPT_TRUNCATE);
    if (ret == CKR_OK)
        ret = corrupt_state_and_check("bad magic", CORRUPT_MAGIC);
    if (ret == CKR_OK)
        ret = corrupt_state_and_check("bad scheme param", CORRUPT_PARAM);
    if (ret == CKR_OK)
        ret = corrupt_state_and_check("flipped GCM tag", CORRUPT_TAG);
    return ret;
}
#endif /* !_WIN32 */

/* ---- Phase 2: parameter matrix ---- */
typedef struct {
    const char* name;
    CK_ULONG levels;
    CK_ULONG lms;
    CK_ULONG lmots;
    CK_ULONG capacity;   /* 2^(levels*height) */
    int fast;            /* 1 = part of the default fast subset */
} HssParamSet;

static const HssParamSet paramSets[] = {
    { "L1/H5/W1",  1, CKL_LMS_SHA256_M32_H5,  CKL_LMOTS_SHA256_N32_W1,   32, 0 },
    { "L1/H5/W2",  1, CKL_LMS_SHA256_M32_H5,  CKL_LMOTS_SHA256_N32_W2,   32, 0 },
    { "L1/H5/W4",  1, CKL_LMS_SHA256_M32_H5,  CKL_LMOTS_SHA256_N32_W4,   32, 1 },
    { "L1/H5/W8",  1, CKL_LMS_SHA256_M32_H5,  CKL_LMOTS_SHA256_N32_W8,   32, 0 },
    { "L1/H10/W4", 1, CKL_LMS_SHA256_M32_H10, CKL_LMOTS_SHA256_N32_W4, 1024, 0 },
    { "L2/H5/W4",  2, CKL_LMS_SHA256_M32_H5,  CKL_LMOTS_SHA256_N32_W4, 1024, 1 },
};

/* keygen -> sign x2 -> verify -> reload -> confirm counter preserved -> sign
 * -> verify, for one parameter set. Each set gets a fresh token. */
static CK_RV run_param_set(const HssParamSet* ps)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-param";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0, remaining = 0, remaining2 = 0;
    int i;

    printf("    [%s] keygen/sign/verify/reload...\n", ps->name);
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, ps->levels, ps->lms, ps->lmots,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "param-set keygen");
    }
    if (ret == CKR_OK) {
        ret = get_keys_remaining(session, priv, &remaining);
        CHECK_CKR(ret, "param-set keys-remaining");
    }
    if (ret == CKR_OK && remaining != ps->capacity) {
        fprintf(stderr, "\n[%s] capacity %lu, expected %lu - FAIL\n", ps->name,
            (unsigned long)remaining, (unsigned long)ps->capacity);
        ret = CKR_GENERAL_ERROR;
    }
    for (i = 0; ret == CKR_OK && i < 2; i++) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        if (ret == CKR_OK)
            ret = hss_verify(session, pub, sig, sigLen);
        CHECK_CKR(ret, "param-set pre-reload sign/verify");
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    /* Reload and confirm the counter survived (capacity - 2 signs). */
    close_session(session);
    session = CK_INVALID_HANDLE;
    pkcs11_final();
    if (ret == CKR_OK)
        ret = reopen_token(&session);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
    if (ret == CKR_OK)
        ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1, &pub);
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &remaining2);
    if (ret == CKR_OK && remaining2 != ps->capacity - 2) {
        fprintf(stderr, "\n[%s] post-reload remaining %lu, expected %lu "
            "- FAIL\n", ps->name, (unsigned long)remaining2,
            (unsigned long)(ps->capacity - 2));
        ret = CKR_GENERAL_ERROR;
    }
    if (ret == CKR_OK)
        ret = hss_sign(session, priv, &sig, &sigLen);
    if (ret == CKR_OK)
        ret = hss_verify(session, pub, sig, sigLen);
    CHECK_CKR(ret, "param-set post-reload sign/verify");
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

static CK_RV test_param_matrix(void)
{
    CK_RV ret = CKR_OK;
    int full = 0, i, n;

#ifndef WOLFPKCS11_NO_ENV
    if (XGETENV("WOLFPKCS11_HSS_FULL_MATRIX") != NULL)
        full = 1;
#endif
    n = (int)(sizeof(paramSets) / sizeof(paramSets[0]));
    printf("  parameter matrix (%s)...\n", full ? "full" : "fast subset");
    for (i = 0; ret == CKR_OK && i < n; i++) {
        if (!full && !paramSets[i].fast)
            continue;
        ret = run_param_set(&paramSets[i]);
    }
    if (ret == CKR_OK && !full) {
        printf("    (set WOLFPKCS11_HSS_FULL_MATRIX=1 for W1/W2/W8 and H10)\n");
    }
    return ret;
}

/* Multi-level HSS (L2/H5): the lower subtree holds 2^5 = 32 one-time keys.
 * Signing past that boundary exhausts the lower tree and advances the parent to
 * a fresh subtree - the most error-prone HSS state transition. Confirm signing
 * across the boundary verifies on both sides and that a reload straddling the
 * boundary resumes correctly. */
static CK_RV test_multilevel_rollover(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    static CK_BYTE id[] = "hss-rollover";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0, remaining = 0;
    const int crossAt = 32;   /* lower-subtree size, 2^5 */
    const int total = 36;     /* a few signatures past the boundary */
    int i;

    printf("  multi-level (L2/H5) subtree rollover...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, 2, CKL_LMS_SHA256_M32_H5,
            CKL_LMOTS_SHA256_N32_W4, id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "L2 keygen");
    }
    for (i = 0; ret == CKR_OK && i < total; i++) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        if (ret == CKR_OK)
            ret = hss_verify(session, pub, sig, sigLen);
        CHECK_CKR(ret, "rollover sign/verify");
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
        /* Reload right after crossing into the second subtree. */
        if (ret == CKR_OK && i == crossAt) {
            printf("    --- reload straddling the subtree boundary ---\n");
            close_session(session);
            session = CK_INVALID_HANDLE;
            pkcs11_final();
            ret = reopen_token(&session);
            if (ret == CKR_OK)
                ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1,
                    &priv);
            if (ret == CKR_OK)
                ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1,
                    &pub);
            CHECK_CKR(ret, "reload across boundary");
        }
    }
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &remaining);
    if (ret == CKR_OK && remaining != (CK_ULONG)(1024 - total)) {
        fprintf(stderr, "\nrollover: remaining %lu, expected %d - FAIL\n",
            (unsigned long)remaining, 1024 - total);
        ret = CKR_GENERAL_ERROR;
    }
    if (sig != NULL)
        XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    close_session(session);
    pkcs11_final();
    return ret;
}

/* Destroying an unrelated token object renumbers the survivors, which unstores
 * and re-stores them. The re-store rewrites only the object shell, so if the
 * renumbering path also dropped the signature-state file the surviving private
 * key would be permanently unusable. Destroy the PUBLIC key, which sits after
 * the private key in the token list and so forces the private key through the
 * renumbering loop, then reload and sign. */
static CK_RV test_destroy_sibling_keeps_state(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-sibling";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;

    printf("  destroying the public key keeps the private state...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    /* One signature so the on-disk state is past the genesis index. */
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "baseline sign");
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
    }
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, pub);
        CHECK_CKR(ret, "C_DestroyObject(public)");
    }
    close_session(session);
    pkcs11_final();

    /* Reload the token: the private key must still decode and sign. */
    if (ret == CKR_OK) {
        ret = reopen_token(&session);
        CHECK_CKR(ret, "reopen after destroying the public key");
    }
    if (ret == CKR_OK) {
        ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1, &priv);
        CHECK_CKR(ret, "private key survived");
    }
    if (ret == CKR_OK) {
        ret = hss_sign(session, priv, &sig, &sigLen);
        CHECK_CKR(ret, "sign after the sibling was destroyed");
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
        if (ret == CKR_OK)
            printf("    private key still signs\n");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A spent key cannot be reloaded - wolfSSL rejects a key with no signatures
 * left. That must not take the whole token down: C_Login has to succeed so the
 * other objects stay reachable, while the spent key itself reports
 * CKR_DEVICE_ERROR. */
static CK_RV test_exhausted_key_login(void)
{
    CK_RV ret, sret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aes = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-spent";
    CK_BYTE aesId[] = "aes-bystander";
    CK_MECHANISM mech;
    CK_BYTE sig[4096];
    CK_ULONG sigLen;
    int i;
    CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
    CK_KEY_TYPE aesType = CKK_AES;
    CK_BYTE aesKey[32] = { 0 };
    CK_ATTRIBUTE aesTmpl[] = {
        { CKA_CLASS,    &secretClass, sizeof(secretClass) },
        { CKA_KEY_TYPE, &aesType,     sizeof(aesType)     },
        { CKA_TOKEN,    &ckTrue,      sizeof(ckTrue)      },
        { CKA_ID,       aesId,        sizeof(aesId) - 1   },
        { CKA_VALUE,    aesKey,       sizeof(aesKey)      },
    };

    mech.mechanism = CKM_HSS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    printf("  an exhausted key does not break login for the token...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    /* An unrelated token object that must remain reachable afterwards. */
    if (ret == CKR_OK) {
        ret = funcList->C_CreateObject(session, aesTmpl,
            sizeof(aesTmpl) / sizeof(*aesTmpl), &aes);
        CHECK_CKR(ret, "create bystander AES key");
    }
    /* Spend the whole tree. */
    for (i = 0; ret == CKR_OK && i < HSS_H5_SIGS + 4; i++) {
        sret = funcList->C_SignInit(session, &mech, priv);
        if (sret != CKR_OK)
            break;
        sigLen = sizeof(sig);
        sret = funcList->C_Sign(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, sig,
            &sigLen);
        if (sret != CKR_OK)
            break;
    }
    close_session(session);
    pkcs11_final();

    /* The whole point: login must still work. */
    if (ret == CKR_OK) {
        ret = reopen_token(&session);
        CHECK_CKR(ret, "C_Login with an exhausted HSS key on the token");
    }
    if (ret == CKR_OK) {
        ret = find_by_id(session, CKO_SECRET_KEY, aesId, sizeof(aesId) - 1,
            &aes);
        CHECK_CKR(ret, "bystander key still reachable");
    }
    if (ret == CKR_OK) {
        printf("    login succeeded, other objects reachable\n");
        /* A key whose state cannot be reloaded stays flagged as undecoded,
         * which is how this library already treats any object it could not
         * decode for the current user: wp11_Session_FindNext skips it. So the
         * spent key is not enumerable rather than enumerable-but-erroring.
         * Assert that, and that it is the ONLY thing lost - the token and its
         * other objects keep working. */
        if (find_by_id_quiet(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1,
                &priv) == CKR_OK) {
            /* Should it become enumerable one day, it must still refuse. */
            sret = funcList->C_SignInit(session, &mech, priv);
            if (sret == CKR_OK) {
                sigLen = sizeof(sig);
                sret = funcList->C_Sign(session, (CK_BYTE*)testMsg,
                    TEST_MSG_LEN, sig, &sigLen);
            }
            CHECK_CKR_FAIL(sret, CKR_DEVICE_ERROR, "spent-key sign");
            if (sret != CKR_DEVICE_ERROR)
                ret = CKR_GENERAL_ERROR;
            else
                printf("    spent key reports CKR_DEVICE_ERROR\n");
        }
        else {
            printf("    spent key not enumerable, token otherwise intact\n");
        }
    }
    /* The bystander key must still be usable and destroyable, proving the
     * token is fully operational and not merely loggable-into. */
    if (ret == CKR_OK) {
        ret = funcList->C_DestroyObject(session, aes);
        CHECK_CKR(ret, "C_DestroyObject on the bystander key");
    }
    close_session(session);
    pkcs11_final();
    return ret;
}

/* C_Logout re-encodes the live objects with protect set, which releases the
 * signing key; the next C_Login decodes it again from the durable state. Both
 * halves happen inside one C_Initialize, a path no other test covers. Run it
 * twice so a leak or a stale key surfaces on the second cycle. */
static CK_RV test_logout_login_cycle(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-cycle";
    CK_BYTE* sig = NULL;
    CK_ULONG sigLen = 0;
    CK_ULONG remaining = 0, prevRemaining = 0;
    int cycle;

    printf("  logout/login cycle keeps the key usable...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK)
        ret = get_keys_remaining(session, priv, &prevRemaining);

    for (cycle = 0; ret == CKR_OK && cycle < 2; cycle++) {
        if (ret == CKR_OK) {
            ret = funcList->C_Logout(session);
            CHECK_CKR(ret, "C_Logout");
        }
        if (ret == CKR_OK) {
            ret = funcList->C_Login(session, CKU_USER, userPin, userPinLen);
            CHECK_CKR(ret, "C_Login after logout");
        }
        if (ret == CKR_OK) {
            ret = find_by_id(session, CKO_PRIVATE_KEY, id, sizeof(id) - 1,
                &priv);
            CHECK_CKR(ret, "private key after re-login");
        }
        if (ret == CKR_OK) {
            ret = hss_sign(session, priv, &sig, &sigLen);
            CHECK_CKR(ret, "sign after re-login");
        }
        if (ret == CKR_OK) {
            ret = find_by_id(session, CKO_PUBLIC_KEY, id, sizeof(id) - 1,
                &pub);
        }
        if (ret == CKR_OK)
            ret = hss_verify(session, pub, sig, sigLen);
        if (sig != NULL) {
            XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            sig = NULL;
        }
        /* The index must move forward across the cycle, never back. */
        if (ret == CKR_OK) {
            ret = get_keys_remaining(session, priv, &remaining);
            CHECK_CKR(ret, "keys-remaining after cycle");
        }
        if (ret == CKR_OK && remaining >= prevRemaining) {
            fprintf(stderr,
                "\nkeys-remaining did not advance across cycle %d "
                "(%lu -> %lu) - FAIL\n", cycle,
                (unsigned long)prevRemaining, (unsigned long)remaining);
            ret = CKR_GENERAL_ERROR;
        }
        prevRemaining = remaining;
    }
    if (ret == CKR_OK)
        printf("    two logout/login cycles, state advanced each time\n");
    close_session(session);
    pkcs11_final();
    return ret;
}

/* A second C_SignInit while an HSS signing operation is already active must be
 * refused. This only works if WP11_INIT_HSS_SIGN is registered as a sign-class
 * operation; if it is not, the second init silently replaces the first. */
static CK_RV test_sign_init_operation_active(void)
{
    CK_RV ret, sret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
    CK_BYTE id[] = "hss-active";
    CK_MECHANISM mech;
    CK_BYTE sig[4096];
    CK_ULONG sigLen;

    mech.mechanism = CKM_HSS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    printf("  a second C_SignInit is refused while one is active...\n");
    ret = fresh_token(&session);
    if (ret == CKR_OK) {
        ret = gen_hss_key(session, hssLevels, hssLmsType, hssLmotsType,
            id, sizeof(id) - 1, &pub, &priv);
        CHECK_CKR(ret, "keygen");
    }
    if (ret == CKR_OK) {
        ret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR(ret, "first C_SignInit");
    }
    if (ret == CKR_OK) {
        sret = funcList->C_SignInit(session, &mech, priv);
        CHECK_CKR_FAIL(sret, CKR_OPERATION_ACTIVE, "second C_SignInit");
        if (sret != CKR_OPERATION_ACTIVE)
            ret = CKR_GENERAL_ERROR;
        else
            printf("    second C_SignInit returned CKR_OPERATION_ACTIVE\n");
    }
    /* The first operation must still be the live one and complete normally. */
    if (ret == CKR_OK) {
        sigLen = sizeof(sig);
        ret = funcList->C_Sign(session, (CK_BYTE*)testMsg, TEST_MSG_LEN, sig,
            &sigLen);
        CHECK_CKR(ret, "C_Sign completes the original operation");
    }
    if (ret == CKR_OK)
        ret = hss_verify(session, pub, sig, sigLen);
    close_session(session);
    pkcs11_final();
    return ret;
}

static CK_RV run_all(void)
{
    CK_RV ret;

    ret = test_keygen_sign_verify();
    if (ret == CKR_OK)
        ret = test_reload_no_rollback();
    if (ret == CKR_OK)
        ret = test_keygen_negative_templates();
    if (ret == CKR_OK)
        ret = test_keys_remaining_private();
    if (ret == CKR_OK)
        ret = test_import_value_rejected();
    if (ret == CKR_OK)
        ret = test_exhaustion_poison();
    if (ret == CKR_OK)
        ret = test_sign_init_operation_active();
    if (ret == CKR_OK)
        ret = test_exhausted_key_login();
    if (ret == CKR_OK)
        ret = test_logout_login_cycle();
    if (ret == CKR_OK)
        ret = test_destroy_sibling_keeps_state();
    if (ret == CKR_OK)
        ret = test_param_matrix();
    if (ret == CKR_OK)
        ret = test_multilevel_rollover();
#ifndef _WIN32
    if (ret == CKR_OK)
        ret = test_destroy_removes_state();
    if (ret == CKR_OK)
        ret = test_state_tamper_detected();
    if (ret == CKR_OK)
        ret = test_write_failure_poison();
    if (ret == CKR_OK)
        ret = test_crash_durability();
    if (ret == CKR_OK)
        ret = test_corruption_matrix();
#endif
    return ret;
}
#endif /* WOLFPKCS11_LMS_PRIVATE && !WOLFPKCS11_NO_STORE */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
#if defined(WOLFPKCS11_LMS_PRIVATE) && !defined(WOLFPKCS11_NO_STORE)
    {
        CK_RV ret;

#ifndef WOLFPKCS11_NO_ENV
        if (!XGETENV("WOLFPKCS11_TOKEN_PATH"))
            XSETENV("WOLFPKCS11_TOKEN_PATH", storeDir, 1);
        else
            storeDir = XGETENV("WOLFPKCS11_TOKEN_PATH");
#endif

        printf("wolfPKCS11 LMS/HSS private-key (sign) test\n");
        printf("=========================================\n\n");

        ret = run_all();

        cleanup_store();
        if (ret == CKR_OK) {
            printf("\nAll tests passed!\n");
            return 0;
        }
        printf("\nTest failed with error: %lx\n", (unsigned long)ret);
        return 1;
    }
#else
    printf("LMS/HSS sign support (--enable-lms-private) not compiled in!\n");
    return 77;
#endif
}
