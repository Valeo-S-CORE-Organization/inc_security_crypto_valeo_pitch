// *******************************************************************************
// Copyright (c) 2026 Contributors to the Eclipse Foundation
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

//! The Test demonstrates:
//!   - Loading the PKCS#11 library.
//!   - Connecting to a token: C_Initialize → C_OpenSession → C_Login.
//!   - Disconnecting from a token: C_Logout → C_CloseSession → C_Finalize.

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use cryptoki::pkcs11::{
    C_CloseSession, C_Encrypt, C_EncryptInit, C_GenerateKey, C_GetSessionInfo, C_InitPIN, C_InitToken, C_Initialize,
    C_Login, C_Logout, C_OpenSession,
};
use serial_test::serial;
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

// ── connectToSlot / disconnectFromSlot ───────

/// Demonstrates the full connect/disconnect lifecycle:
///   C_Initialize → C_OpenSession → C_Login → C_Logout → C_CloseSession
///
/// connectToSlot():
///   C_Initialize(NULL_PTR)
///   C_OpenSession(slotId, CKF_SERIAL_SESSION|CKF_RW_SESSION, ...)
///   C_Login(hSession, CKU_USER, slotPin, pinLen)
///
/// disconnectFromSlot():
///   C_Logout(hSession)
///   C_CloseSession(hSession)
///   C_Finalize(NULL_PTR)
#[test]
#[serial]
fn connect_disconnect() {
    init();
    unsafe {
        // Step 1: Initialize the library
        // (shared via Once — mirrors C_Initialize(NULL_PTR) in loadHSMLibrary)

        // Step 2: Open a read-write session on the slot
        // (C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession))
        let mut h_session: CK_SESSION_HANDLE = 0;
        assert_eq!(
            C_OpenSession(
                0,
                CKF_SERIAL_SESSION | CKF_RW_SESSION,
                ptr::null_mut(),
                None,
                &mut h_session,
            ),
            CKR_OK,
            "C_OpenSession failed",
        );
        assert_ne!(h_session, 0, "session handle must be non-zero");

        // Step 3: Login as normal user
        // (C_Login(hSession, CKU_USER, slotPin, strlen(slotPin)))
        let rv_login = C_Login(h_session, CKU_USER, SLOT_PIN.as_ptr(), SLOT_PIN.len() as CK_ULONG);
        assert!(
            rv_login == CKR_OK || rv_login == CKR_USER_ALREADY_LOGGED_IN,
            "C_Login failed: {rv_login:#x}"
        );

        // Step 4: Verify session state reflects logged-in user
        let mut info: CK_SESSION_INFO = std::mem::zeroed();
        assert_eq!(C_GetSessionInfo(h_session, &mut info), CKR_OK);
        assert_eq!(
            info.state, CKS_RW_USER_FUNCTIONS,
            "state must be CKS_RW_USER_FUNCTIONS after login"
        );

        // Step 5: Logout
        // (C_Logout(hSession))
        let rv_logout = C_Logout(h_session);
        assert!(
            rv_logout == CKR_OK || rv_logout == CKR_USER_NOT_LOGGED_IN,
            "C_Logout failed: {rv_logout:#x}"
        );

        // Step 6: Verify session state reverts to public read-write
        assert_eq!(C_GetSessionInfo(h_session, &mut info), CKR_OK);
        assert_eq!(info.state, CKS_RW_PUBLIC_SESSION, "state must revert after logout");

        // Step 7: Close the session
        // (C_CloseSession(hSession))
        assert_eq!(C_CloseSession(h_session), CKR_OK, "C_CloseSession failed");
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// PERFORMANCE PROOF
// ═════════════════════════════════════════════════════════════════════════════

#[test]
#[serial]
fn prove_cpp_setup_bottleneck() {
    use std::time::Instant;
    init();
    unsafe {
        println!("--- PROVING C++ SetUp() BOTTLENECK ---");

        let so_pin = b"so-pin"; // Use the correct default SO PIN
        let user_pin = b"1234";
        let label = b"Test Token                      "; // 32 bytes padded

        // 1. C_InitToken (Computes Argon2id hash for SO PIN)
        let t0 = Instant::now();
        assert_eq!(
            C_InitToken(0, so_pin.as_ptr(), so_pin.len() as CK_ULONG, label.as_ptr()),
            CKR_OK
        );
        let d_init_token = t0.elapsed();

        let mut h: CK_SESSION_HANDLE = 0;
        C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, ptr::null_mut(), None, &mut h);

        // 2. C_Login SO (Computes Argon2id hash to verify SO PIN)
        let t1 = Instant::now();
        assert_eq!(C_Login(h, CKU_SO, so_pin.as_ptr(), so_pin.len() as CK_ULONG), CKR_OK);
        let d_login_so = t1.elapsed();

        // 3. C_InitPIN (Computes Argon2id hash for User PIN)
        let t2 = Instant::now();
        assert_eq!(C_InitPIN(h, user_pin.as_ptr(), user_pin.len() as CK_ULONG), CKR_OK);
        let d_init_pin = t2.elapsed();

        C_Logout(h);

        // 4. C_Login User (Computes Argon2id hash to verify User PIN)
        let t3 = Instant::now();
        assert_eq!(
            C_Login(h, CKU_USER, user_pin.as_ptr(), user_pin.len() as CK_ULONG),
            CKR_OK
        );
        let d_login_user = t3.elapsed();

        // 5. Generate Key & Encrypt (To contrast the heavy login vs lightweight crypto)
        let key_len: u64 = 16;
        let key_len_bytes = key_len.to_le_bytes();
        let mut template = [CK_ATTRIBUTE {
            r#type: CKA_VALUE_LEN,
            pValue: key_len_bytes.as_ptr() as *mut _,
            ulValueLen: 8,
        }];
        let mech_gen = CK_MECHANISM {
            mechanism: CKM_AES_KEY_GEN,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut key_handle = 0;
        assert_eq!(
            C_GenerateKey(h, &mech_gen, template.as_mut_ptr(), 1, &mut key_handle),
            CKR_OK
        );

        let iv = [0u8; 16];
        let mech_enc = CK_MECHANISM {
            mechanism: CKM_AES_CBC_PAD,
            pParameter: iv.as_ptr() as *mut _,
            ulParameterLen: 16,
        };
        assert_eq!(C_EncryptInit(h, &mech_enc, key_handle), CKR_OK);

        let plaintext = [0u8; 16];
        let mut ciphertext = [0u8; 32];
        let mut ct_len = 32;

        let t4 = Instant::now();
        assert_eq!(
            C_Encrypt(h, plaintext.as_ptr(), 16, ciphertext.as_mut_ptr(), &mut ct_len),
            CKR_OK
        );
        let d_encrypt = t4.elapsed();

        C_CloseSession(h);

        let total = d_init_token + d_login_so + d_init_pin + d_login_user;
        println!("1. C_InitToken (Hashes SO PIN)   : {:.2?}", d_init_token);
        println!("2. C_Login SO  (Verifies SO PIN) : {:.2?}", d_login_so);
        println!("3. C_InitPIN   (Hashes User PIN) : {:.2?}", d_init_pin);
        println!("4. C_Login User(Verifies User PIN): {:.2?}", d_login_user);
        println!("--------------------------------------");
        println!("Total time for ONE C++ SetUp()   : {:.2?}", total);
        println!("----------------------------------");
        println!("5. C_Encrypt   (Actual crypto)   : {:.2?}", d_encrypt);
        println!("----------------------------------");
    }
}
