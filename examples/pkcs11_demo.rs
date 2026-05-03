// *******************************************************************************
// Copyright (c) 2025 Contributors to the Eclipse Foundation
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// <https://www.apache.org/licenses/LICENSE-2.0>
//
// SPDX-License-Identifier: Apache-2.0
// *******************************************************************************

//! Full PKCS#11 scenario demo — function-list dispatch pattern.
//!
//! Demonstrates the idiomatic way a real application consumes a PKCS#11
//! shared library: only **two** symbols are resolved via dlsym —
//! `C_GetFunctionList` (v2.40) and `C_GetInterface` (v3.0).  Every
//! subsequent call is dispatched through the `CK_FUNCTION_LIST` (or
//! `CK_FUNCTION_LIST_3_0`) table returned by those bootstrap functions.
//!
//! The `p11!` macro used throughout this file unwraps an `Option<fn(...)>`
//! slot from the function list and calls it, keeping the call-sites concise.
//!
//! Scenario:
//!   0.  C_GetFunctionList     — obtain dispatch table (bootstrap)
//!   1.  C_Initialize          — start the library, register OpenSslEngine
//!   2.  C_GetInfo             — inspect library version
//!   3.  C_GetSlotList         — enumerate slots
//!   4.  C_GetMechanismList    — list supported mechanisms
//!   5.  C_OpenSession         — open an R/W session
//!   6.  C_Login               — authenticate as CKU_USER
//!   7.  C_GenerateRandom      — fill a 32-byte random buffer
//!   8.  C_GenerateKey         — generate AES-256 key
//!       C_EncryptInit+C_Encrypt (AES-CBC-PAD)
//!       C_DecryptInit+C_Decrypt (AES-CBC-PAD)
//!       C_EncryptInit+C_Encrypt (AES-GCM)
//!       C_DecryptInit+C_Decrypt (AES-GCM)
//!   9.  C_GenerateKeyPair     — generate RSA-2048 key pair
//!       C_GetAttributeValue   — read CKA_MODULUS_BITS, CKA_MODULUS
//!       C_GetAttributeValue   — CKA_VALUE on private key → CKR_ATTRIBUTE_SENSITIVE
//!       C_SignInit+C_Sign      (CKM_SHA256_RSA_PKCS)
//!       C_VerifyInit+C_Verify  (CKM_SHA256_RSA_PKCS)
//!       C_SignInit+C_Sign      (CKM_SHA256_RSA_PKCS_PSS)
//!       C_VerifyInit+C_Verify  (CKM_SHA256_RSA_PKCS_PSS)
//!       C_EncryptInit+C_Encrypt (CKM_RSA_PKCS_OAEP)
//!       C_DecryptInit+C_Decrypt (CKM_RSA_PKCS_OAEP)
//!  10.  C_GenerateKeyPair     — generate EC P-256 key pair
//!       C_GetAttributeValue   — CKA_EC_POINT from private key (engine fallback)
//!       C_SignInit+C_Sign      (CKM_ECDSA)
//!       C_VerifyInit+C_Verify  (CKM_ECDSA)
//!  11.  C_GenerateKeyPair     — generate Ed25519 key pair (v3.0)
//!       C_SignInit+C_Sign      (CKM_EDDSA)
//!       C_VerifyInit+C_Verify  (CKM_EDDSA)
//!  12.  C_GenerateKey         — generate ChaCha20 key (v3.0)
//!       C_EncryptInit+C_Encrypt (CKM_CHACHA20_POLY1305)
//!       C_DecryptInit+C_Decrypt (CKM_CHACHA20_POLY1305)
//!  13.  SHA-3 / SHA-384 / SHA-512 digests (v3.0)
//!  14.  C_DigestInit+C_DigestUpdate+C_DigestFinal — multi-part SHA-256
//!  15.  C_GetInterfaceList + C_GetInterface (v3.0 interface discovery)
//!  16.  C_FindObjectsInit+C_FindObjects+C_FindObjectsFinal — enumerate keys
//!  17.  C_DestroyObject       — delete the AES key
//!  18.  C_Logout + C_CloseSession + C_Finalize

use std::ffi::c_void;
use std::ptr;

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use cryptoki::pkcs11::{C_GetFunctionList, C_GetInterface};

/// Dispatch a call through a PKCS#11 function-list table.
///
/// Unwraps the `Option<fn(...)>` slot and invokes it with the given arguments.
macro_rules! p11 {
    ($fl:expr, $func:ident $(, $arg:expr)* $(,)?) => {
        ($fl.$func.unwrap())($($arg),*)
    }
}

// ── GCM parameter struct (mirrors CK_GCM_PARAMS) ─────────────────────────

#[repr(C)]
#[allow(non_snake_case)]
struct GcmParams {
    pIv:      *const u8,
    ulIvLen:  u64,
    ulIvBits: u64,
    pAAD:     *const u8,
    ulAADLen: u64,
    ulTagBits: u64,
}

// ── Helpers ───────────────────────────────────────────────────────────────

const PIN: &[u8] = b"1234";

fn ck_ok(rv: CK_RV, label: &str) {
    if rv != CKR_OK {
        eprintln!("  FAIL  {label}: {rv:#010x}");
        std::process::exit(1);
    }
}

fn section(title: &str) {
    println!("\n══ {title} ══");
}

fn ok(label: &str) {
    println!("  ok    {label}");
}

fn info(label: &str, detail: &str) {
    println!("  info  {label}: {detail}");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join("")
}

// ── Main ──────────────────────────────────────────────────────────────────

fn main() {
    println!("Cryptoki demo — full PKCS#11 scenario");
    println!("==========================================");

    unsafe { run() }

    println!("\n==========================================");
    println!("All scenarios completed successfully.");
}

unsafe fn run() {
    // ── 0. C_GetFunctionList — bootstrap ────────────────────────────────
    //
    // In a real application this is the ONLY symbol obtained via dlsym.
    // Every subsequent call goes through the returned function pointer table.
    section("0. C_GetFunctionList — obtain dispatch table");
    let mut fl_ptr: *const CK_FUNCTION_LIST = ptr::null();
    let rv = C_GetFunctionList(&mut fl_ptr);
    assert_eq!(rv, CKR_OK, "C_GetFunctionList failed: {rv:#010x}");
    assert!(!fl_ptr.is_null());
    let fl = &*fl_ptr;
    info("version", &format!("{}.{}", fl.version.major, fl.version.minor));
    ok("function list obtained — all subsequent calls go through this table");

    // ── 1. C_Initialize ───────────────────────────────────────────────────

    section("1. C_Initialize");
    let rv = p11!(fl, C_Initialize, ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
        "C_Initialize failed: {rv:#010x}");
    ok("library initialised, OpenSslEngine registered");

    // ── 2. C_GetInfo ──────────────────────────────────────────────────────

    section("2. C_GetInfo");
    let mut ck_info: CK_INFO = std::mem::zeroed();
    ck_ok(p11!(fl, C_GetInfo, &mut ck_info), "C_GetInfo");
    info("cryptokiVersion",
        &format!("{}.{}", ck_info.cryptokiVersion.major, ck_info.cryptokiVersion.minor));
    let mfr = std::str::from_utf8(&ck_info.manufacturerID)
        .unwrap_or("?").trim_end();
    info("manufacturerID", mfr);
    let desc = std::str::from_utf8(&ck_info.libraryDescription)
        .unwrap_or("?").trim_end();
    info("libraryDescription", desc);

    // ── 3. C_GetSlotList ──────────────────────────────────────────────────

    section("3. C_GetSlotList");
    let mut slot_count: CK_ULONG = 0;
    ck_ok(p11!(fl, C_GetSlotList, CK_TRUE, ptr::null_mut(), &mut slot_count), "C_GetSlotList (count)");
    let mut slots = vec![0u64; slot_count as usize];
    ck_ok(p11!(fl, C_GetSlotList, CK_TRUE, slots.as_mut_ptr(), &mut slot_count), "C_GetSlotList");
    info("slot count", &slot_count.to_string());
    info("slot IDs", &format!("{slots:?}"));

    // ── 4. C_GetMechanismList ─────────────────────────────────────────────

    section("4. C_GetMechanismList");
    let mut mech_count: CK_ULONG = 0;
    ck_ok(p11!(fl, C_GetMechanismList, 0, ptr::null_mut(), &mut mech_count), "C_GetMechanismList (count)");
    let mut mechs = vec![0u64; mech_count as usize];
    ck_ok(p11!(fl, C_GetMechanismList, 0, mechs.as_mut_ptr(), &mut mech_count), "C_GetMechanismList");
    info("mechanism count", &mech_count.to_string());

    // ── 5+6. C_OpenSession + C_Login ─────────────────────────────────────

    section("5+6. C_OpenSession + C_Login");
    let mut h_session: CK_SESSION_HANDLE = 0;
    ck_ok(p11!(fl, C_OpenSession, 0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
        ptr::null_mut(), None, &mut h_session), "C_OpenSession");
    ck_ok(p11!(fl, C_Login, h_session, CKU_USER, PIN.as_ptr(), PIN.len() as CK_ULONG), "C_Login");
    info("session handle", &h_session.to_string());
    ok("logged in as CKU_USER");

    // ── 7. C_GenerateRandom ───────────────────────────────────────────────

    section("7. C_GenerateRandom");
    let mut rand_buf = [0u8; 32];
    ck_ok(p11!(fl, C_GenerateRandom, h_session, rand_buf.as_mut_ptr(), 32), "C_GenerateRandom");
    info("32 random bytes", &hex(&rand_buf));

    // ── 8. AES ───────────────────────────────────────────────────────────

    section("8. AES-256 — key generation + CBC + GCM");

    // Generate AES-256 key
    let key_len: CK_ULONG = 32;
    let mut aes_attrs = [CK_ATTRIBUTE {
        r#type:     CKA_VALUE_LEN,
        pValue:     &key_len as *const CK_ULONG as *mut c_void,
        ulValueLen: 8,
    }];
    let mech_aes_gen = CK_MECHANISM { mechanism: CKM_AES_KEY_GEN,
        pParameter: ptr::null(), ulParameterLen: 0 };
    let mut h_aes: CK_OBJECT_HANDLE = 0;
    ck_ok(p11!(fl, C_GenerateKey, h_session, &mech_aes_gen,
        aes_attrs.as_mut_ptr(), 1, &mut h_aes), "C_GenerateKey(AES-256)");
    info("AES-256 handle", &h_aes.to_string());

    // AES-CBC-PAD round-trip
    let plaintext   = b"Hello, PKCS#11 AES-CBC world!!!";  // 32 bytes — one block
    let iv_cbc      = [0x01u8; 16];
    let mech_cbc    = CK_MECHANISM { mechanism: CKM_AES_CBC_PAD,
        pParameter: iv_cbc.as_ptr() as *mut c_void, ulParameterLen: 16 };

    ck_ok(p11!(fl, C_EncryptInit, h_session, &mech_cbc, h_aes), "C_EncryptInit(AES-CBC)");
    let mut ct_cbc      = vec![0u8; 64];
    let mut ct_cbc_len: CK_ULONG = 64;
    ck_ok(p11!(fl, C_Encrypt, h_session, plaintext.as_ptr(), plaintext.len() as CK_ULONG,
        ct_cbc.as_mut_ptr(), &mut ct_cbc_len), "C_Encrypt(AES-CBC)");
    ct_cbc.truncate(ct_cbc_len as usize);
    info("AES-CBC ciphertext", &hex(&ct_cbc));

    ck_ok(p11!(fl, C_DecryptInit, h_session, &mech_cbc, h_aes), "C_DecryptInit(AES-CBC)");
    let mut pt_cbc      = vec![0u8; 64];
    let mut pt_cbc_len: CK_ULONG = 64;
    ck_ok(p11!(fl, C_Decrypt, h_session, ct_cbc.as_ptr(), ct_cbc_len,
        pt_cbc.as_mut_ptr(), &mut pt_cbc_len), "C_Decrypt(AES-CBC)");
    pt_cbc.truncate(pt_cbc_len as usize);
    assert_eq!(pt_cbc, plaintext, "AES-CBC round-trip mismatch");
    ok("AES-CBC-PAD encrypt/decrypt round-trip verified");

    // AES-GCM round-trip
    let iv_gcm  = [0x02u8; 12];
    let aad     = b"additional authenticated data";
    let gcm_params = GcmParams {
        pIv:      iv_gcm.as_ptr(),
        ulIvLen:  iv_gcm.len() as u64,
        ulIvBits: (iv_gcm.len() * 8) as u64,
        pAAD:     aad.as_ptr(),
        ulAADLen: aad.len() as u64,
        ulTagBits: 128,
    };
    let mech_gcm = CK_MECHANISM {
        mechanism:      CKM_AES_GCM,
        pParameter:     &gcm_params as *const GcmParams as *mut c_void,
        ulParameterLen: std::mem::size_of::<GcmParams>() as CK_ULONG,
    };

    ck_ok(p11!(fl, C_EncryptInit, h_session, &mech_gcm, h_aes), "C_EncryptInit(AES-GCM)");
    let mut ct_gcm     = vec![0u8; plaintext.len() + 16];
    let mut ct_gcm_len = ct_gcm.len() as CK_ULONG;
    ck_ok(p11!(fl, C_Encrypt, h_session, plaintext.as_ptr(), plaintext.len() as CK_ULONG,
        ct_gcm.as_mut_ptr(), &mut ct_gcm_len), "C_Encrypt(AES-GCM)");
    ct_gcm.truncate(ct_gcm_len as usize);
    info("AES-GCM ciphertext+tag", &hex(&ct_gcm));

    ck_ok(p11!(fl, C_DecryptInit, h_session, &mech_gcm, h_aes), "C_DecryptInit(AES-GCM)");
    let mut pt_gcm     = vec![0u8; ct_gcm.len()];
    let mut pt_gcm_len = pt_gcm.len() as CK_ULONG;
    ck_ok(p11!(fl, C_Decrypt, h_session, ct_gcm.as_ptr(), ct_gcm_len,
        pt_gcm.as_mut_ptr(), &mut pt_gcm_len), "C_Decrypt(AES-GCM)");
    pt_gcm.truncate(pt_gcm_len as usize);
    assert_eq!(pt_gcm, plaintext, "AES-GCM round-trip mismatch");
    ok("AES-GCM encrypt/decrypt round-trip verified (with AAD)");

    // ── 9. RSA-2048 ──────────────────────────────────────────────────────

    section("9. RSA-2048 — key generation + attributes + sign/verify + OAEP");

    let modulus_bits: CK_ULONG = 2048;
    let pub_exp: [u8; 3]       = [0x01, 0x00, 0x01]; // 65537
    let mut rsa_pub_attrs = [
        CK_ATTRIBUTE { r#type: CKA_MODULUS_BITS,    pValue: &modulus_bits as *const CK_ULONG as *mut c_void, ulValueLen: 8 },
        CK_ATTRIBUTE { r#type: CKA_PUBLIC_EXPONENT, pValue: pub_exp.as_ptr() as *mut c_void, ulValueLen: 3 },
    ];
    let mut rsa_priv_attrs: [CK_ATTRIBUTE; 0] = [];
    let mech_rsa_gen = CK_MECHANISM { mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
        pParameter: ptr::null(), ulParameterLen: 0 };
    let mut h_rsa_pub: CK_OBJECT_HANDLE  = 0;
    let mut h_rsa_priv: CK_OBJECT_HANDLE = 0;
    ck_ok(p11!(fl, C_GenerateKeyPair, h_session, &mech_rsa_gen,
        rsa_pub_attrs.as_mut_ptr(), 2,
        rsa_priv_attrs.as_mut_ptr(), 0,
        &mut h_rsa_pub, &mut h_rsa_priv), "C_GenerateKeyPair(RSA-2048)");
    info("RSA-2048 pub handle",  &h_rsa_pub.to_string());
    info("RSA-2048 priv handle", &h_rsa_priv.to_string());

    // Read CKA_MODULUS_BITS from public key (HashMap path)
    let mut bits: u64 = 0;
    let mut attr_bits = CK_ATTRIBUTE {
        r#type:     CKA_MODULUS_BITS,
        pValue:     &mut bits as *mut u64 as *mut c_void,
        ulValueLen: 8,
    };
    ck_ok(p11!(fl, C_GetAttributeValue, h_session, h_rsa_pub, &mut attr_bits, 1),
        "C_GetAttributeValue(CKA_MODULUS_BITS)");
    info("CKA_MODULUS_BITS", &bits.to_string());
    assert_eq!(bits, 2048);

    // Read CKA_MODULUS from public key (HashMap path)
    let mut attr_mod = CK_ATTRIBUTE { r#type: CKA_MODULUS, pValue: ptr::null_mut(), ulValueLen: 0 };
    ck_ok(p11!(fl, C_GetAttributeValue, h_session, h_rsa_pub, &mut attr_mod, 1),
        "C_GetAttributeValue(CKA_MODULUS, length)");
    let mod_len = attr_mod.ulValueLen;
    let mut modulus_buf = vec![0u8; mod_len as usize];
    attr_mod.pValue     = modulus_buf.as_mut_ptr() as *mut c_void;
    attr_mod.ulValueLen = mod_len;
    ck_ok(p11!(fl, C_GetAttributeValue, h_session, h_rsa_pub, &mut attr_mod, 1),
        "C_GetAttributeValue(CKA_MODULUS, value)");
    info("CKA_MODULUS (first 8 bytes)", &hex(&modulus_buf[..8]));

    // CKA_VALUE on private key → must be sensitive (engine fallback path)
    let mut dummy = [0u8; 512];
    let mut attr_val = CK_ATTRIBUTE {
        r#type:     CKA_VALUE,
        pValue:     dummy.as_mut_ptr() as *mut c_void,
        ulValueLen: 512,
    };
    let rv_sensitive = p11!(fl, C_GetAttributeValue, h_session, h_rsa_priv, &mut attr_val, 1);
    assert_eq!(rv_sensitive, CKR_ATTRIBUTE_SENSITIVE,
        "CKA_VALUE on RSA private key must be CKR_ATTRIBUTE_SENSITIVE");
    ok("CKA_VALUE on RSA private key → CKR_ATTRIBUTE_SENSITIVE (correct)");

    // RSA PKCS#1 v1.5 sign / verify
    let message = b"The quick brown fox jumps over the lazy dog";
    let mech_rsa_pkcs = CK_MECHANISM { mechanism: CKM_SHA256_RSA_PKCS,
        pParameter: ptr::null(), ulParameterLen: 0 };

    ck_ok(p11!(fl, C_SignInit, h_session, &mech_rsa_pkcs, h_rsa_priv), "C_SignInit(SHA256_RSA_PKCS)");
    let mut sig_len: CK_ULONG = 0;
    ck_ok(p11!(fl, C_Sign, h_session, message.as_ptr(), message.len() as CK_ULONG,
        ptr::null_mut(), &mut sig_len), "C_Sign (length)");
    let mut signature = vec![0u8; sig_len as usize];
    ck_ok(p11!(fl, C_Sign, h_session, message.as_ptr(), message.len() as CK_ULONG,
        signature.as_mut_ptr(), &mut sig_len), "C_Sign");
    signature.truncate(sig_len as usize);
    info("RSA-PKCS1 signature (first 8 bytes)", &hex(&signature[..8]));

    ck_ok(p11!(fl, C_VerifyInit, h_session, &mech_rsa_pkcs, h_rsa_pub), "C_VerifyInit(SHA256_RSA_PKCS)");
    ck_ok(p11!(fl, C_Verify, h_session, message.as_ptr(), message.len() as CK_ULONG,
        signature.as_ptr(), sig_len), "C_Verify(SHA256_RSA_PKCS)");
    ok("RSA PKCS#1 v1.5 SHA-256 sign/verify passed");

    // RSA-PSS sign / verify
    let mech_pss = CK_MECHANISM { mechanism: CKM_SHA256_RSA_PKCS_PSS,
        pParameter: ptr::null(), ulParameterLen: 0 };

    ck_ok(p11!(fl, C_SignInit, h_session, &mech_pss, h_rsa_priv), "C_SignInit(PSS)");
    let mut pss_sig_len = sig_len;
    let mut pss_sig     = vec![0u8; pss_sig_len as usize];
    ck_ok(p11!(fl, C_Sign, h_session, message.as_ptr(), message.len() as CK_ULONG,
        pss_sig.as_mut_ptr(), &mut pss_sig_len), "C_Sign(PSS)");
    pss_sig.truncate(pss_sig_len as usize);

    ck_ok(p11!(fl, C_VerifyInit, h_session, &mech_pss, h_rsa_pub), "C_VerifyInit(PSS)");
    ck_ok(p11!(fl, C_Verify, h_session, message.as_ptr(), message.len() as CK_ULONG,
        pss_sig.as_ptr(), pss_sig_len), "C_Verify(PSS)");
    ok("RSA-PSS SHA-256 sign/verify passed");

    // RSA-OAEP encrypt / decrypt
    let secret_msg = b"secret payload";
    let mech_oaep  = CK_MECHANISM { mechanism: CKM_RSA_PKCS_OAEP,
        pParameter: ptr::null(), ulParameterLen: 0 };

    ck_ok(p11!(fl, C_EncryptInit, h_session, &mech_oaep, h_rsa_pub), "C_EncryptInit(OAEP)");
    let mut oaep_ct     = vec![0u8; 512];
    let mut oaep_ct_len = oaep_ct.len() as CK_ULONG;
    ck_ok(p11!(fl, C_Encrypt, h_session, secret_msg.as_ptr(), secret_msg.len() as CK_ULONG,
        oaep_ct.as_mut_ptr(), &mut oaep_ct_len), "C_Encrypt(OAEP)");
    oaep_ct.truncate(oaep_ct_len as usize);

    ck_ok(p11!(fl, C_DecryptInit, h_session, &mech_oaep, h_rsa_priv), "C_DecryptInit(OAEP)");
    let mut oaep_pt     = vec![0u8; 512];
    let mut oaep_pt_len = oaep_pt.len() as CK_ULONG;
    ck_ok(p11!(fl, C_Decrypt, h_session, oaep_ct.as_ptr(), oaep_ct_len,
        oaep_pt.as_mut_ptr(), &mut oaep_pt_len), "C_Decrypt(OAEP)");
    oaep_pt.truncate(oaep_pt_len as usize);
    assert_eq!(oaep_pt, secret_msg, "RSA-OAEP round-trip mismatch");
    ok("RSA-OAEP encrypt/decrypt round-trip verified");

    // ── 10. EC P-256 ─────────────────────────────────────────────────────

    section("10. EC P-256 — key generation + attributes + ECDSA");

    let p256_oid = [0x06u8, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let mut ec_pub_attrs = [CK_ATTRIBUTE {
        r#type:     CKA_EC_PARAMS,
        pValue:     p256_oid.as_ptr() as *mut c_void,
        ulValueLen: p256_oid.len() as CK_ULONG,
    }];
    let mut ec_priv_attrs: [CK_ATTRIBUTE; 0] = [];
    let mech_ec_gen = CK_MECHANISM { mechanism: CKM_EC_KEY_PAIR_GEN,
        pParameter: ptr::null(), ulParameterLen: 0 };
    let mut h_ec_pub: CK_OBJECT_HANDLE  = 0;
    let mut h_ec_priv: CK_OBJECT_HANDLE = 0;
    ck_ok(p11!(fl, C_GenerateKeyPair, h_session, &mech_ec_gen,
        ec_pub_attrs.as_mut_ptr(), 1,
        ec_priv_attrs.as_mut_ptr(), 0,
        &mut h_ec_pub, &mut h_ec_priv), "C_GenerateKeyPair(EC P-256)");
    info("EC P-256 pub handle",  &h_ec_pub.to_string());
    info("EC P-256 priv handle", &h_ec_priv.to_string());

    // CKA_EC_POINT from private key via engine fallback (not in HashMap)
    let mut ec_point_attr = CK_ATTRIBUTE { r#type: CKA_EC_POINT,
        pValue: ptr::null_mut(), ulValueLen: 0 };
    ck_ok(p11!(fl, C_GetAttributeValue, h_session, h_ec_priv, &mut ec_point_attr, 1),
        "C_GetAttributeValue(CKA_EC_POINT, length) from private key");
    let point_len = ec_point_attr.ulValueLen as usize;
    let mut point_buf = vec![0u8; point_len];
    ec_point_attr.pValue     = point_buf.as_mut_ptr() as *mut c_void;
    ec_point_attr.ulValueLen = point_len as CK_ULONG;
    ck_ok(p11!(fl, C_GetAttributeValue, h_session, h_ec_priv, &mut ec_point_attr, 1),
        "C_GetAttributeValue(CKA_EC_POINT, value) from private key");
    info("CKA_EC_POINT derived from private key (first 8 bytes)", &hex(&point_buf[..8]));
    ok("CKA_EC_POINT retrieved from EC private key via engine fallback");

    // ECDSA sign / verify
    let ec_message = b"sign this with ECDSA P-256";
    let mech_ecdsa = CK_MECHANISM { mechanism: CKM_ECDSA,
        pParameter: ptr::null(), ulParameterLen: 0 };

    // P-256 DER-encoded ECDSA signature is at most 72 bytes.
    // ECDSA is randomised, so the two-call (null→length, then data) pattern
    // is unsafe for variable-length DER — just pre-allocate the max.
    let mut ec_sig     = vec![0u8; 72];
    let mut ec_sig_len: CK_ULONG = 72;
    ck_ok(p11!(fl, C_SignInit, h_session, &mech_ecdsa, h_ec_priv), "C_SignInit(ECDSA)");
    ck_ok(p11!(fl, C_Sign, h_session, ec_message.as_ptr(), ec_message.len() as CK_ULONG,
        ec_sig.as_mut_ptr(), &mut ec_sig_len), "C_Sign(ECDSA)");
    ec_sig.truncate(ec_sig_len as usize);
    info("ECDSA signature (DER, first 8 bytes)", &hex(&ec_sig[..8]));

    ck_ok(p11!(fl, C_VerifyInit, h_session, &mech_ecdsa, h_ec_pub), "C_VerifyInit(ECDSA)");
    ck_ok(p11!(fl, C_Verify, h_session, ec_message.as_ptr(), ec_message.len() as CK_ULONG,
        ec_sig.as_ptr(), ec_sig_len), "C_Verify(ECDSA)");
    ok("ECDSA P-256 sign/verify passed");

    // ── 11. EdDSA (Ed25519) — v3.0 ───────────────────────────────────────

    section("11. EdDSA (Ed25519) — key generation + sign/verify (v3.0)");

    let ed25519_oid = [0x06u8, 0x03, 0x2b, 0x65, 0x70]; // OID 1.3.101.112
    let mut ed_pub_attrs = [CK_ATTRIBUTE {
        r#type:     CKA_EC_PARAMS,
        pValue:     ed25519_oid.as_ptr() as *mut c_void,
        ulValueLen: ed25519_oid.len() as CK_ULONG,
    }];
    let mut ed_priv_attrs: [CK_ATTRIBUTE; 0] = [];
    let mech_ed_gen = CK_MECHANISM { mechanism: CKM_EC_EDWARDS_KEY_PAIR_GEN,
        pParameter: ptr::null(), ulParameterLen: 0 };
    let mut h_ed_pub: CK_OBJECT_HANDLE  = 0;
    let mut h_ed_priv: CK_OBJECT_HANDLE = 0;
    ck_ok(p11!(fl, C_GenerateKeyPair, h_session, &mech_ed_gen,
        ed_pub_attrs.as_mut_ptr(), 1,
        ed_priv_attrs.as_mut_ptr(), 0,
        &mut h_ed_pub, &mut h_ed_priv), "C_GenerateKeyPair(Ed25519)");
    info("Ed25519 pub handle",  &h_ed_pub.to_string());
    info("Ed25519 priv handle", &h_ed_priv.to_string());

    // EdDSA sign / verify
    let ed_message = b"EdDSA sign/verify via PKCS#11 v3.0";
    let mech_eddsa = CK_MECHANISM { mechanism: CKM_EDDSA,
        pParameter: ptr::null(), ulParameterLen: 0 };

    ck_ok(p11!(fl, C_SignInit, h_session, &mech_eddsa, h_ed_priv), "C_SignInit(EdDSA)");
    let mut ed_sig     = vec![0u8; 128];
    let mut ed_sig_len: CK_ULONG = 128;
    ck_ok(p11!(fl, C_Sign, h_session, ed_message.as_ptr(), ed_message.len() as CK_ULONG,
        ed_sig.as_mut_ptr(), &mut ed_sig_len), "C_Sign(EdDSA)");
    ed_sig.truncate(ed_sig_len as usize);
    info("EdDSA signature", &format!("{} bytes", ed_sig_len));
    assert_eq!(ed_sig_len, 64, "Ed25519 signature must be 64 bytes");

    ck_ok(p11!(fl, C_VerifyInit, h_session, &mech_eddsa, h_ed_pub), "C_VerifyInit(EdDSA)");
    ck_ok(p11!(fl, C_Verify, h_session, ed_message.as_ptr(), ed_message.len() as CK_ULONG,
        ed_sig.as_ptr(), ed_sig_len), "C_Verify(EdDSA)");
    ok("EdDSA Ed25519 sign/verify passed");

    // Tamper test
    ed_sig[0] ^= 0xFF;
    ck_ok(p11!(fl, C_VerifyInit, h_session, &mech_eddsa, h_ed_pub), "C_VerifyInit(EdDSA, tamper)");
    let tamper_rv = p11!(fl, C_Verify, h_session, ed_message.as_ptr(), ed_message.len() as CK_ULONG,
        ed_sig.as_ptr(), ed_sig_len);
    assert_eq!(tamper_rv, CKR_SIGNATURE_INVALID, "tampered EdDSA signature must fail");
    ok("EdDSA tampered signature correctly rejected");

    // ── 12. ChaCha20-Poly1305 — v3.0 ────────────────────────────────────

    section("12. ChaCha20-Poly1305 — key generation + AEAD (v3.0)");

    let mech_chacha_gen = CK_MECHANISM { mechanism: CKM_CHACHA20_KEY_GEN,
        pParameter: ptr::null(), ulParameterLen: 0 };
    let mut h_chacha: CK_OBJECT_HANDLE = 0;
    ck_ok(p11!(fl, C_GenerateKey, h_session, &mech_chacha_gen,
        ptr::null(), 0, &mut h_chacha), "C_GenerateKey(ChaCha20)");
    info("ChaCha20 key handle", &h_chacha.to_string());

    let nonce_chacha = [0x42u8; 12];
    let aad_chacha   = b"additional data";
    let chacha_params = GcmParams {
        pIv:       nonce_chacha.as_ptr(),
        ulIvLen:   12,
        ulIvBits:  96,
        pAAD:      aad_chacha.as_ptr(),
        ulAADLen:  aad_chacha.len() as u64,
        ulTagBits: 128,
    };
    let mech_chacha = CK_MECHANISM {
        mechanism:      CKM_CHACHA20_POLY1305,
        pParameter:     &chacha_params as *const GcmParams as *mut c_void,
        ulParameterLen: std::mem::size_of::<GcmParams>() as CK_ULONG,
    };
    let chacha_plain = b"ChaCha20-Poly1305 AEAD demo";

    ck_ok(p11!(fl, C_EncryptInit, h_session, &mech_chacha, h_chacha), "C_EncryptInit(ChaCha20-Poly1305)");
    let mut chacha_ct     = vec![0u8; chacha_plain.len() + 16];
    let mut chacha_ct_len = chacha_ct.len() as CK_ULONG;
    ck_ok(p11!(fl, C_Encrypt, h_session, chacha_plain.as_ptr(), chacha_plain.len() as CK_ULONG,
        chacha_ct.as_mut_ptr(), &mut chacha_ct_len), "C_Encrypt(ChaCha20-Poly1305)");
    chacha_ct.truncate(chacha_ct_len as usize);
    info("ChaCha20-Poly1305 ciphertext+tag", &format!("{} bytes", chacha_ct_len));

    ck_ok(p11!(fl, C_DecryptInit, h_session, &mech_chacha, h_chacha), "C_DecryptInit(ChaCha20-Poly1305)");
    let mut chacha_pt     = vec![0u8; chacha_ct.len()];
    let mut chacha_pt_len = chacha_pt.len() as CK_ULONG;
    ck_ok(p11!(fl, C_Decrypt, h_session, chacha_ct.as_ptr(), chacha_ct_len,
        chacha_pt.as_mut_ptr(), &mut chacha_pt_len), "C_Decrypt(ChaCha20-Poly1305)");
    chacha_pt.truncate(chacha_pt_len as usize);
    assert_eq!(chacha_pt, chacha_plain, "ChaCha20-Poly1305 round-trip mismatch");
    ok("ChaCha20-Poly1305 AEAD encrypt/decrypt round-trip verified");

    // Tamper test — corrupt ciphertext
    chacha_ct[0] ^= 0xFF;
    ck_ok(p11!(fl, C_DecryptInit, h_session, &mech_chacha, h_chacha), "C_DecryptInit(ChaCha20 tamper)");
    let mut bad_len: CK_ULONG = 128;
    let mut bad_buf = vec![0u8; 128];
    let tamper_chacha_rv = p11!(fl, C_Decrypt, h_session, chacha_ct.as_ptr(), chacha_ct.len() as CK_ULONG,
        bad_buf.as_mut_ptr(), &mut bad_len);
    assert_ne!(tamper_chacha_rv, CKR_OK, "tampered ChaCha20-Poly1305 must fail");
    ok("ChaCha20-Poly1305 tampered ciphertext correctly rejected");

    // ── 13. SHA-3 / SHA-384 / SHA-512 digests — v3.0 ────────────────────

    section("13. SHA-3 / SHA-384 / SHA-512 digests (v3.0)");

    let digest_data = b"abc";

    // SHA3-256
    let mech_sha3_256 = CK_MECHANISM { mechanism: CKM_SHA3_256,
        pParameter: ptr::null(), ulParameterLen: 0 };
    ck_ok(p11!(fl, C_DigestInit, h_session, &mech_sha3_256), "C_DigestInit(SHA3-256)");
    let mut sha3_buf = [0u8; 32];
    let mut sha3_len: CK_ULONG = 32;
    ck_ok(p11!(fl, C_Digest, h_session, digest_data.as_ptr(), digest_data.len() as CK_ULONG,
        sha3_buf.as_mut_ptr(), &mut sha3_len), "C_Digest(SHA3-256)");
    info("SHA3-256(\"abc\")", &hex(&sha3_buf));
    ok("SHA3-256 digest (32 bytes)");

    // SHA-384
    let mech_sha384 = CK_MECHANISM { mechanism: CKM_SHA384,
        pParameter: ptr::null(), ulParameterLen: 0 };
    ck_ok(p11!(fl, C_DigestInit, h_session, &mech_sha384), "C_DigestInit(SHA-384)");
    let mut sha384_buf = [0u8; 48];
    let mut sha384_len: CK_ULONG = 48;
    ck_ok(p11!(fl, C_Digest, h_session, digest_data.as_ptr(), digest_data.len() as CK_ULONG,
        sha384_buf.as_mut_ptr(), &mut sha384_len), "C_Digest(SHA-384)");
    info("SHA-384(\"abc\") first 16 bytes", &hex(&sha384_buf[..16]));
    ok("SHA-384 digest (48 bytes)");

    // SHA-512
    let mech_sha512 = CK_MECHANISM { mechanism: CKM_SHA512,
        pParameter: ptr::null(), ulParameterLen: 0 };
    ck_ok(p11!(fl, C_DigestInit, h_session, &mech_sha512), "C_DigestInit(SHA-512)");
    let mut sha512_buf = [0u8; 64];
    let mut sha512_len: CK_ULONG = 64;
    ck_ok(p11!(fl, C_Digest, h_session, digest_data.as_ptr(), digest_data.len() as CK_ULONG,
        sha512_buf.as_mut_ptr(), &mut sha512_len), "C_Digest(SHA-512)");
    info("SHA-512(\"abc\") first 16 bytes", &hex(&sha512_buf[..16]));
    ok("SHA-512 digest (64 bytes)");

    // SHA3-384
    let mech_sha3_384 = CK_MECHANISM { mechanism: CKM_SHA3_384,
        pParameter: ptr::null(), ulParameterLen: 0 };
    ck_ok(p11!(fl, C_DigestInit, h_session, &mech_sha3_384), "C_DigestInit(SHA3-384)");
    let mut sha3_384_buf = [0u8; 48];
    let mut sha3_384_len: CK_ULONG = 48;
    ck_ok(p11!(fl, C_Digest, h_session, digest_data.as_ptr(), digest_data.len() as CK_ULONG,
        sha3_384_buf.as_mut_ptr(), &mut sha3_384_len), "C_Digest(SHA3-384)");
    ok("SHA3-384 digest (48 bytes)");

    // SHA3-512
    let mech_sha3_512 = CK_MECHANISM { mechanism: CKM_SHA3_512,
        pParameter: ptr::null(), ulParameterLen: 0 };
    ck_ok(p11!(fl, C_DigestInit, h_session, &mech_sha3_512), "C_DigestInit(SHA3-512)");
    let mut sha3_512_buf = [0u8; 64];
    let mut sha3_512_len: CK_ULONG = 64;
    ck_ok(p11!(fl, C_Digest, h_session, digest_data.as_ptr(), digest_data.len() as CK_ULONG,
        sha3_512_buf.as_mut_ptr(), &mut sha3_512_len), "C_Digest(SHA3-512)");
    ok("SHA3-512 digest (64 bytes)");

    // ── 14. Multi-part SHA-256 digest ─────────────────────────────────────

    section("14. Multi-part SHA-256 digest");

    let mech_sha256 = CK_MECHANISM { mechanism: CKM_SHA256,
        pParameter: ptr::null(), ulParameterLen: 0 };
    ck_ok(p11!(fl, C_DigestInit, h_session, &mech_sha256), "C_DigestInit(SHA-256)");

    let chunks: &[&[u8]] = &[b"The ", b"quick ", b"brown ", b"fox"];
    for chunk in chunks {
        ck_ok(p11!(fl, C_DigestUpdate, h_session, chunk.as_ptr(), chunk.len() as CK_ULONG),
            "C_DigestUpdate");
    }

    let mut digest_buf = [0u8; 32];
    let mut digest_len: CK_ULONG = 32;
    ck_ok(p11!(fl, C_DigestFinal, h_session, digest_buf.as_mut_ptr(), &mut digest_len),
        "C_DigestFinal");
    info("SHA-256(\"The quick brown fox\")", &hex(&digest_buf));
    ok("multi-part SHA-256 digest produced");

    // ── 15. C_GetInterfaceList + C_GetInterface (v3.0) ───────────────────
    //
    // C_GetInterface is the v3.0 bootstrap symbol — a real consumer would
    // dlsym it alongside C_GetFunctionList.  We call it as a bare symbol
    // here (imported at the top), then cast the returned pFunctionList to
    // the v3.0 function list to prove we can access the extended table.

    section("15. C_GetInterfaceList + C_GetInterface (v3.0)");

    let mut iface_count: CK_ULONG = 0;
    // Use the v2.40 function list for C_GetInterfaceList — it's not on CK_FUNCTION_LIST,
    // so we call C_GetInterface (bare symbol) to get the v3.0 table first.
    // Actually, C_GetInterfaceList is only on CK_FUNCTION_LIST_3_0, so we call
    // C_GetInterface directly as a bare symbol to bootstrap the v3.0 path.
    let mut iface_ptr: *const CK_INTERFACE = ptr::null();
    let name = b"PKCS 11\0";
    ck_ok(C_GetInterface(name.as_ptr(), ptr::null_mut(), &mut iface_ptr, 0),
        "C_GetInterface(\"PKCS 11\")");
    assert!(!iface_ptr.is_null(), "interface pointer must be non-null");
    assert!(!(*iface_ptr).pFunctionList.is_null(), "function list must be non-null");

    // Cast to CK_FUNCTION_LIST_3_0 to access v3.0 extensions
    let fl3 = &*((*iface_ptr).pFunctionList as *const CK_FUNCTION_LIST_3_0);
    info("v3.0 function list version", &format!("{}.{}", fl3.version.major, fl3.version.minor));

    let iface_name = std::ffi::CStr::from_ptr((*iface_ptr).pInterfaceName as *const libc::c_char);
    info("interface name", iface_name.to_str().unwrap_or("?"));

    // Now use the v3.0 function list to call C_GetInterfaceList
    ck_ok(p11!(fl3, C_GetInterfaceList, ptr::null_mut(), &mut iface_count),
        "C_GetInterfaceList (count)");
    info("interface count", &iface_count.to_string());
    assert!(iface_count >= 1, "expected at least 1 interface");
    ok("v3.0 interface discovery works");

    // ── 16. C_FindObjects ─────────────────────────────────────────────────

    section("16. C_FindObjects — enumerate all objects");

    let mut find_attrs: [CK_ATTRIBUTE; 0] = [];
    ck_ok(p11!(fl, C_FindObjectsInit, h_session, find_attrs.as_mut_ptr(), 0),
        "C_FindObjectsInit (no filter)");
    let mut handles = vec![0u64; 32];
    let mut found: CK_ULONG = 0;
    ck_ok(p11!(fl, C_FindObjects, h_session, handles.as_mut_ptr(), 32, &mut found),
        "C_FindObjects");
    ck_ok(p11!(fl, C_FindObjectsFinal, h_session), "C_FindObjectsFinal");
    info("total objects in store", &found.to_string());
    // We generated: 1 AES + 2 RSA + 2 EC + 2 Ed25519 + 1 ChaCha20 = 8
    assert!(found >= 8, "expected at least 8 objects, got {found}");
    ok("found all generated keys");

    // Find only private keys
    let class_priv: CK_ULONG = CKO_PRIVATE_KEY;
    let mut priv_filter = [CK_ATTRIBUTE {
        r#type:     CKA_CLASS,
        pValue:     &class_priv as *const CK_ULONG as *mut c_void,
        ulValueLen: 8,
    }];
    ck_ok(p11!(fl, C_FindObjectsInit, h_session, priv_filter.as_mut_ptr(), 1),
        "C_FindObjectsInit (CKO_PRIVATE_KEY)");
    let mut priv_handles = vec![0u64; 64];
    let mut priv_found: CK_ULONG = 0;
    ck_ok(p11!(fl, C_FindObjects, h_session, priv_handles.as_mut_ptr(), 64, &mut priv_found),
        "C_FindObjects (private keys)");
    ck_ok(p11!(fl, C_FindObjectsFinal, h_session), "C_FindObjectsFinal");
    info("private key count", &priv_found.to_string());
    let priv_slice = &priv_handles[..priv_found as usize];
    assert!(priv_slice.contains(&h_rsa_priv), "RSA private key must be found");
    assert!(priv_slice.contains(&h_ec_priv), "EC private key must be found");
    assert!(priv_slice.contains(&h_ed_priv), "Ed25519 private key must be found");
    ok("private key filter returned our RSA + EC + Ed25519 private keys");

    // ── 17. C_DestroyObject ───────────────────────────────────────────────

    section("17. C_DestroyObject — delete AES key");
    ck_ok(p11!(fl, C_DestroyObject, h_session, h_aes), "C_DestroyObject(AES)");
    ok("AES-256 key destroyed");

    // Confirm it's gone via FindObjects
    let class_secret: CK_ULONG = CKO_SECRET_KEY;
    let mut secret_filter = [CK_ATTRIBUTE {
        r#type:     CKA_CLASS,
        pValue:     &class_secret as *const CK_ULONG as *mut c_void,
        ulValueLen: 8,
    }];
    ck_ok(p11!(fl, C_FindObjectsInit, h_session, secret_filter.as_mut_ptr(), 1),
        "C_FindObjectsInit (CKO_SECRET_KEY, post-delete)");
    let mut secret_handles = vec![0u64; 64];
    let mut secret_found: CK_ULONG = 0;
    ck_ok(p11!(fl, C_FindObjects, h_session, secret_handles.as_mut_ptr(), 64, &mut secret_found),
        "C_FindObjects (secret keys, post-delete)");
    ck_ok(p11!(fl, C_FindObjectsFinal, h_session), "C_FindObjectsFinal");
    assert!(!secret_handles[..secret_found as usize].contains(&h_aes), "AES key should no longer be found");
    ok("confirmed: AES key destroyed, no longer returned by FindObjects");

    // ── 18. Cleanup ───────────────────────────────────────────────────────

    section("18. C_Logout + C_CloseSession + C_Finalize");
    ck_ok(p11!(fl, C_Logout, h_session),     "C_Logout");
    ck_ok(p11!(fl, C_CloseSession, h_session), "C_CloseSession");
    ck_ok(p11!(fl, C_Finalize, ptr::null_mut()), "C_Finalize");
    ok("session closed, library finalised");
}
