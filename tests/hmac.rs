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

//! HMAC sign/verify integration tests.
//!
//! Each test follows:
//!   C_Initialize → C_OpenSession + C_Login
//!   → C_GenerateKey (CKM_GENERIC_SECRET_KEY_GEN)
//!   → C_SignInit + C_Sign  (compute MAC)
//!   → C_VerifyInit + C_Verify  (validate MAC)
//!   → tamper: verify fails on wrong data
//!   → C_Logout + C_CloseSession

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use cryptoki::pkcs11::{
    C_Initialize,
    C_OpenSession, C_CloseSession,
    C_Login, C_Logout,
    C_GenerateKey,
    C_SignInit, C_Sign,
    C_VerifyInit, C_Verify,
};
use std::ffi::c_void;
use std::ptr;
use std::sync::Once;

const SLOT_PIN: &[u8] = b"1234";

static INIT: Once = Once::new();

fn init() {
    INIT.call_once(|| unsafe {
        let rv = C_Initialize(ptr::null_mut());
        assert!(
            rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED,
            "C_Initialize failed: {rv:#010x}",
        );
    });
}

unsafe fn connect_to_slot() -> CK_SESSION_HANDLE {
    let mut h: CK_SESSION_HANDLE = 0;
    assert_eq!(
        C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, ptr::null_mut(), None, &mut h),
        CKR_OK,
    );
    let rv = C_Login(h, CKU_USER, SLOT_PIN.as_ptr(), SLOT_PIN.len() as CK_ULONG);
    assert!(rv == CKR_OK || rv == CKR_USER_ALREADY_LOGGED_IN, "C_Login failed: {rv:#x}");
    h
}

unsafe fn disconnect_from_slot(h: CK_SESSION_HANDLE) {
    let rv = C_Logout(h);
    assert!(rv == CKR_OK || rv == CKR_USER_NOT_LOGGED_IN, "C_Logout failed: {rv:#x}");
    assert_eq!(C_CloseSession(h), CKR_OK);
}

/// Generate a generic secret key of `key_len` bytes — the natural key type for HMAC.
/// OpenSSL HMAC accepts arbitrary-length keys; 32 bytes is a solid default.
unsafe fn generate_hmac_key(h: CK_SESSION_HANDLE, key_len: u64) -> CK_OBJECT_HANDLE {
    let key_type = CKK_GENERIC_SECRET as CK_ULONG;
    let key_len_ulong = key_len as CK_ULONG;
    let true_val = CK_TRUE as CK_BBOOL;
    let mut attribs = [
        CK_ATTRIBUTE {
            r#type: CKA_KEY_TYPE,
            pValue: &key_type as *const _ as *mut c_void,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            r#type: CKA_VALUE_LEN,
            pValue: &key_len_ulong as *const _ as *mut c_void,
            ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            r#type: CKA_SIGN,
            pValue: &true_val as *const _ as *mut c_void,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
        CK_ATTRIBUTE {
            r#type: CKA_VERIFY,
            pValue: &true_val as *const _ as *mut c_void,
            ulValueLen: std::mem::size_of::<CK_BBOOL>() as CK_ULONG,
        },
    ];
    let mech = CK_MECHANISM {
        mechanism: CKM_GENERIC_SECRET_KEY_GEN,
        pParameter: ptr::null(),
        ulParameterLen: 0,
    };
    let mut key_handle: CK_OBJECT_HANDLE = 0;
    assert_eq!(
        C_GenerateKey(h, &mech, attribs.as_mut_ptr(), attribs.len() as CK_ULONG, &mut key_handle),
        CKR_OK,
        "C_GenerateKey (HMAC) failed",
    );
    key_handle
}

/// Core HMAC sign → verify → tamper-fail cycle for any `mechanism`.
/// `mac_len` is the expected output length in bytes.
unsafe fn hmac_roundtrip(mechanism: CK_MECHANISM_TYPE, mac_len: usize) {
    init();
    let h = connect_to_slot();
    let key = generate_hmac_key(h, mac_len as u64);
    let data = b"The quick brown fox jumps over the lazy dog";

    // ── Sign ──────────────────────────────────────────────────────────────
    let mech = CK_MECHANISM { mechanism, pParameter: ptr::null(), ulParameterLen: 0 };
    assert_eq!(C_SignInit(h, &mech, key), CKR_OK, "C_SignInit failed");

    // length query
    let mut out_len: CK_ULONG = 0;
    assert_eq!(
        C_Sign(h, data.as_ptr(), data.len() as CK_ULONG, ptr::null_mut(), &mut out_len),
        CKR_OK,
        "C_Sign length-query failed",
    );
    assert_eq!(out_len as usize, mac_len, "unexpected MAC length");

    // actual sign
    let mut mac = vec![0u8; mac_len];
    assert_eq!(
        C_Sign(h, data.as_ptr(), data.len() as CK_ULONG, mac.as_mut_ptr(), &mut out_len),
        CKR_OK,
        "C_Sign failed",
    );
    assert_eq!(out_len as usize, mac_len);
    assert!(mac.iter().any(|&b| b != 0), "MAC must not be all-zero");

    // ── Verify (correct data) ─────────────────────────────────────────────
    assert_eq!(C_VerifyInit(h, &mech, key), CKR_OK, "C_VerifyInit failed");
    assert_eq!(
        C_Verify(h, data.as_ptr(), data.len() as CK_ULONG, mac.as_ptr(), out_len),
        CKR_OK,
        "HMAC verification must succeed on correct data",
    );

    // ── Tamper: different data → CKR_SIGNATURE_INVALID ───────────────────
    let wrong_data = b"The quick brown fox jumps over the lazy cat";
    assert_eq!(C_VerifyInit(h, &mech, key), CKR_OK);
    assert_eq!(
        C_Verify(h, wrong_data.as_ptr(), wrong_data.len() as CK_ULONG, mac.as_ptr(), out_len),
        CKR_SIGNATURE_INVALID,
        "tampered data must fail HMAC verification",
    );

    // ── Tamper: flipped MAC byte → CKR_SIGNATURE_INVALID ─────────────────
    let mut bad_mac = mac.clone();
    bad_mac[0] ^= 0xff;
    assert_eq!(C_VerifyInit(h, &mech, key), CKR_OK);
    assert_eq!(
        C_Verify(h, data.as_ptr(), data.len() as CK_ULONG, bad_mac.as_ptr(), out_len),
        CKR_SIGNATURE_INVALID,
        "corrupted MAC must fail HMAC verification",
    );

    disconnect_from_slot(h);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn hmac_sha256_roundtrip() {
    unsafe { hmac_roundtrip(CKM_SHA256_HMAC, 32) }
}

#[test]
fn hmac_sha384_roundtrip() {
    unsafe { hmac_roundtrip(CKM_SHA384_HMAC, 48) }
}

#[test]
fn hmac_sha512_roundtrip() {
    unsafe { hmac_roundtrip(CKM_SHA512_HMAC, 64) }
}

#[test]
fn hmac_key_size_16_bytes() {
    // HMAC is valid with any key size; verify 16-byte key works too.
    unsafe {
        init();
        let h = connect_to_slot();
        let key = generate_hmac_key(h, 16);
        let data = b"short key test";
        let mech = CK_MECHANISM {
            mechanism: CKM_SHA256_HMAC,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        assert_eq!(C_SignInit(h, &mech, key), CKR_OK);
        let mut mac = vec![0u8; 32];
        let mut mac_len: CK_ULONG = 32;
        assert_eq!(
            C_Sign(h, data.as_ptr(), data.len() as CK_ULONG, mac.as_mut_ptr(), &mut mac_len),
            CKR_OK,
        );
        assert_eq!(C_VerifyInit(h, &mech, key), CKR_OK);
        assert_eq!(
            C_Verify(h, data.as_ptr(), data.len() as CK_ULONG, mac.as_ptr(), mac_len),
            CKR_OK,
        );
        disconnect_from_slot(h);
    }
}

#[test]
fn hmac_wrong_mechanism_on_rsa_key_rejected() {
    // CKM_SHA256_HMAC on an RSA key must be rejected at the backend level.
    unsafe {
        use cryptoki::pkcs11::C_GenerateKeyPair;
        init();
        let h = connect_to_slot();
        let key_bits: u64 = 2048;
        let bits_le = key_bits.to_le_bytes();
        let mut pub_attrs = [CK_ATTRIBUTE {
            r#type: CKA_MODULUS_BITS,
            pValue: bits_le.as_ptr() as *mut c_void,
            ulValueLen: 8,
        }];
        let mut priv_attrs: [CK_ATTRIBUTE; 0] = [];
        let keygen_mech = CK_MECHANISM {
            mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        let mut h_pub: CK_OBJECT_HANDLE = 0;
        let mut h_priv: CK_OBJECT_HANDLE = 0;
        assert_eq!(
            C_GenerateKeyPair(h, &keygen_mech, pub_attrs.as_mut_ptr(), 1,
                              priv_attrs.as_mut_ptr(), 0, &mut h_pub, &mut h_priv),
            CKR_OK,
        );
        // C_SignInit accepts (mechanism check only), but C_Sign must fail
        // with CKR_KEY_TYPE_INCONSISTENT when the RSA key is used with HMAC.
        let mech = CK_MECHANISM {
            mechanism: CKM_SHA256_HMAC,
            pParameter: ptr::null(),
            ulParameterLen: 0,
        };
        assert_eq!(C_SignInit(h, &mech, h_priv), CKR_OK);
        let data = b"mismatch";
        let mut mac = vec![0u8; 32];
        let mut mac_len: CK_ULONG = 32;
        let rv = C_Sign(h, data.as_ptr(), data.len() as CK_ULONG, mac.as_mut_ptr(), &mut mac_len);
        assert_eq!(rv, CKR_MECHANISM_INVALID, "RSA key + HMAC mech must be rejected");
        disconnect_from_slot(h);
    }
}
