/* hbs_persistence_test.c
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
 * Token-object persistence test for verify-only LMS/HSS and XMSS/XMSS^MT
 * public keys: import a raw public key as a token object, finalize and
 * re-initialize the library (forcing a reload from disk), then find the key
 * again and confirm it still verifies a known-good signature.
 *
 * For the current verify-only feature a public key is an ordinary token
 * object with no special state, so this only exercises the generic store /
 * reload path. It is deliberately kept as groundwork for the future
 * sign-capable builds: once private keys carry persisted one-time signature
 * state, this test grows to cover that state surviving a reload, which is the
 * part where HBS persistence becomes genuinely feature-specific.
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

#if (defined(WOLFPKCS11_LMS) || defined(WOLFPKCS11_XMSS)) && \
    !defined(WOLFPKCS11_NO_STORE)

#include "hbs_kat.h"

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

static CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
static CK_BBOOL ckTrue = CK_TRUE;

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

/* Create a token public-key object holding a raw HBS public key. */
static CK_RV create_token_pubkey(CK_SESSION_HANDLE session, CK_KEY_TYPE keyType,
    CK_BYTE* id, CK_ULONG idLen, const CK_BYTE* pub, CK_ULONG pubLen,
    CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS,    &pubKeyClass,  sizeof(pubKeyClass) },
        { CKA_KEY_TYPE, &keyType,      sizeof(keyType)     },
        { CKA_TOKEN,    &ckTrue,       sizeof(ckTrue)      },
        { CKA_VERIFY,   &ckTrue,       sizeof(ckTrue)      },
        { CKA_ID,       id,            idLen               },
        { CKA_VALUE,    (CK_BYTE*)pub, pubLen              },
    };

    ret = funcList->C_CreateObject(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl), obj);
    CHECK_CKR(ret, "Create token public key");
    return ret;
}

/* Find the token public key previously created with the given CKA_ID. */
static CK_RV find_token_pubkey(CK_SESSION_HANDLE session, CK_BYTE* id,
    CK_ULONG idLen, CK_OBJECT_HANDLE* obj)
{
    CK_RV ret;
    CK_ULONG count = 0;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &pubKeyClass, sizeof(pubKeyClass) },
        { CKA_ID,    id,           idLen               },
    };

    ret = funcList->C_FindObjectsInit(session, tmpl,
        sizeof(tmpl) / sizeof(*tmpl));
    CHECK_CKR(ret, "FindObjectsInit");
    if (ret == CKR_OK) {
        ret = funcList->C_FindObjects(session, obj, 1, &count);
        CHECK_CKR(ret, "FindObjects");
        funcList->C_FindObjectsFinal(session);
    }
    if (ret == CKR_OK && count != 1) {
        fprintf(stderr, "\nExpected 1 persisted key, found %lu - FAIL\n",
            (unsigned long)count);
        ret = CKR_GENERAL_ERROR;
    }
    return ret;
}

/* Verify a known-good signature, then a one-byte-flipped copy that must be
 * rejected with CKR_SIGNATURE_INVALID. */
static CK_RV verify_good_and_tampered(CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE obj, CK_MECHANISM_TYPE mechType, const CK_BYTE* sig,
    CK_ULONG sigLen)
{
    CK_RV ret;
    CK_MECHANISM mech;
    CK_BYTE* badSig;

    badSig = (CK_BYTE*)XMALLOC(sigLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (badSig == NULL)
        return CKR_HOST_MEMORY;

    mech.mechanism = mechType;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    ret = funcList->C_VerifyInit(session, &mech, obj);
    CHECK_CKR(ret, "VerifyInit (persisted key)");
    if (ret == CKR_OK) {
        ret = funcList->C_Verify(session, hbs_kat_msg, HBS_KAT_MSG_LEN,
            (CK_BYTE*)sig, sigLen);
        CHECK_CKR(ret, "Verify good signature (persisted key)");
    }
    if (ret == CKR_OK) {
        XMEMCPY(badSig, sig, sigLen);
        badSig[sigLen / 2] ^= 0x01;
        ret = funcList->C_VerifyInit(session, &mech, obj);
        CHECK_CKR(ret, "VerifyInit (tampered)");
    }
    if (ret == CKR_OK) {
        CK_RV vret = funcList->C_Verify(session, hbs_kat_msg, HBS_KAT_MSG_LEN,
            badSig, sigLen);
        if (vret != CKR_SIGNATURE_INVALID) {
            fprintf(stderr, "\nTampered signature not rejected: %lx - FAIL\n",
                (unsigned long)vret);
            ret = CKR_GENERAL_ERROR;
        }
    }
    XFREE(badSig, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* One scheme, one phase: phase 1 creates the token public key and verifies;
 * phase 2 finds the persisted key and re-verifies. */
static CK_RV scheme_roundtrip(CK_SESSION_HANDLE session, const char* name,
    CK_KEY_TYPE keyType, CK_MECHANISM_TYPE mechType, CK_BYTE* id,
    CK_ULONG idLen, const CK_BYTE* pub, CK_ULONG pubLen, const CK_BYTE* sig,
    CK_ULONG sigLen, int phase)
{
    CK_RV ret;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;

    if (phase == 1) {
        printf("  [%s] creating token public key and verifying...\n", name);
        ret = create_token_pubkey(session, keyType, id, idLen, pub, pubLen,
            &obj);
        if (ret == CKR_OK)
            ret = verify_good_and_tampered(session, obj, mechType, sig, sigLen);
    }
    else {
        printf("  [%s] finding persisted key and re-verifying...\n", name);
        ret = find_token_pubkey(session, id, idLen, &obj);
        if (ret == CKR_OK)
            ret = verify_good_and_tampered(session, obj, mechType, sig, sigLen);
    }
    return ret;
}

#ifdef WOLFPKCS11_LMS
static CK_BYTE hssId[] = "hbs-persist-hss";
#endif
#ifdef WOLFPKCS11_XMSS
static CK_BYTE xmssId[] = "hbs-persist-xmss";
static CK_BYTE xmssmtId[] = "hbs-persist-xmssmt";
#endif

/* Run every enabled scheme through the given phase (1 = before reinit,
 * 2 = after reinit). */
static CK_RV run_phase(CK_SESSION_HANDLE session, int phase)
{
    CK_RV ret = CKR_OK;

#ifdef WOLFPKCS11_LMS
    if (ret == CKR_OK)
        ret = scheme_roundtrip(session, "HSS", CKK_HSS, CKM_HSS,
            hssId, sizeof(hssId) - 1, hss_kat_pub, sizeof(hss_kat_pub),
            hss_kat_sig, sizeof(hss_kat_sig), phase);
#endif
#ifdef WOLFPKCS11_XMSS
    if (ret == CKR_OK)
        ret = scheme_roundtrip(session, "XMSS", CKK_XMSS, CKM_XMSS,
            xmssId, sizeof(xmssId) - 1, xmss_kat_pub, sizeof(xmss_kat_pub),
            xmss_kat_sig, sizeof(xmss_kat_sig), phase);
    if (ret == CKR_OK)
        ret = scheme_roundtrip(session, "XMSSMT", CKK_XMSSMT,
            CKM_XMSSMT, xmssmtId, sizeof(xmssmtId) - 1, xmssmt_kat_pub,
            sizeof(xmssmt_kat_pub), xmssmt_kat_sig, sizeof(xmssmt_kat_sig),
            phase);
#endif
    return ret;
}

/* Remove the on-disk store artifacts this test creates so repeated runs stay
 * self-contained. remove() on an absent file is a harmless no-op, so removing
 * the superset of possible object/key files (ids 0..2 across the enabled
 * schemes) is safe regardless of which schemes are compiled in. */
static void cleanup_test_files(const char* dir)
{
    char path[512];
    int i;

    if (dir == NULL)
        return;

    snprintf(path, sizeof(path), "%s/wp11_token_0000000000000001", dir);
    (void)remove(path);
    for (i = 0; i <= 2; i++) {
        snprintf(path, sizeof(path),
            "%s/wp11_obj_0000000000000001_%016lx", dir, (unsigned long)i);
        (void)remove(path);
        snprintf(path, sizeof(path),
            "%s/wp11_hsskey_pub_0000000000000001_%016lx", dir, (unsigned long)i);
        (void)remove(path);
        snprintf(path, sizeof(path),
            "%s/wp11_xmsskey_pub_0000000000000001_%016lx", dir, (unsigned long)i);
        (void)remove(path);
    }
}

static CK_RV hbs_persistence_test(void)
{
    CK_RV ret;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

    /* Phase 1: fresh token, create token public keys, verify. */
    ret = pkcs11_init();
    if (ret != CKR_OK)
        return ret;
    if (ret == CKR_OK)
        ret = pkcs11_init_token();
    if (ret == CKR_OK)
        ret = pkcs11_set_user_pin();
    if (ret == CKR_OK)
        ret = pkcs11_open_session(&session);
    if (ret == CKR_OK)
        ret = run_phase(session, 1);
    if (session != CK_INVALID_HANDLE) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
        session = CK_INVALID_HANDLE;
    }
    pkcs11_final();
    if (ret != CKR_OK)
        return ret;

    /* Phase 2: re-initialize (reload from disk), find keys, re-verify. */
    printf("--- re-initializing library (reload from disk) ---\n");
    ret = pkcs11_init();
    if (ret != CKR_OK)
        return ret;
    if (ret == CKR_OK)
        ret = pkcs11_open_session(&session);
    if (ret == CKR_OK)
        ret = run_phase(session, 2);
    if (session != CK_INVALID_HANDLE) {
        funcList->C_Logout(session);
        funcList->C_CloseSession(session);
    }
    pkcs11_final();
    return ret;
}
#endif /* (WOLFPKCS11_LMS || WOLFPKCS11_XMSS) && !WOLFPKCS11_NO_STORE */

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;
#if (defined(WOLFPKCS11_LMS) || defined(WOLFPKCS11_XMSS)) && \
    !defined(WOLFPKCS11_NO_STORE)
    {
        CK_RV ret;

#ifndef WOLFPKCS11_NO_ENV
        if (!XGETENV("WOLFPKCS11_TOKEN_PATH")) {
            XSETENV("WOLFPKCS11_TOKEN_PATH", "./store/hbs", 1);
        }
#endif

        printf("wolfPKCS11 HBS public-key persistence test\n");
        printf("==========================================\n\n");

        ret = hbs_persistence_test();
#ifndef WOLFPKCS11_NO_ENV
        cleanup_test_files(XGETENV("WOLFPKCS11_TOKEN_PATH"));
#endif
        if (ret == CKR_OK) {
            printf("\nAll tests passed!\n");
            return 0;
        }
        printf("\nTest failed with error: %lx\n", (unsigned long)ret);
        return 1;
    }
#else
    printf("LMS/XMSS or key store not compiled in!\n");
    return 77;
#endif
}
