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

//! Real-world PKCS#11 Business Logic Showcase.
//!
//! This example demonstrates how to orchestrate PKCS#11 cryptographic primitives
//! to solve actual business use cases, rather than just testing algorithms in a vacuum.
//!
//! Scenarios covered:
//!   1. Secure Randomness (Session/Nonce generation)
//!   2. Symmetric Encrypted Storage (AES-GCM for database records)
//!   3. Document Signing PKI (ECDSA for digital signatures)
//!   4. Envelope Encryption (AES Key Wrap for secure key exchange/storage)
//!   5. Secure Hashing (SHA-256 for file integrity)

use std::ffi::c_void;
use std::ptr;

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use cryptoki::pkcs11::C_GetFunctionList;

/// Dispatch a call through a PKCS#11 function-list table.
macro_rules! p11 {
    ($fl:expr, $func:ident $(, $arg:expr)* $(,)?) => {
        ($fl.$func.unwrap())($($arg),*)
    }
}

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

fn main() {
    println!("Cryptoki — Business Logic Showcase");
    println!("==========================================");

    unsafe { run() }

    println!("\n==========================================");
    println!("All business scenarios completed successfully.");
}

unsafe fn run() {
    // 1. Bootstrap the token and establish an authenticated session
    let (fl_ptr, h_session) = bootstrap_and_login();
    let fl = &*fl_ptr;

    // 2. Execute isolated, real-world business scenarios
    demo_secure_randomness(fl, h_session);
    demo_symmetric_aead(fl, h_session);
    demo_document_signing_pki(fl, h_session);
    demo_envelope_encryption(fl, h_session);
    demo_secure_hashing(fl, h_session);

    // 3. Teardown
    cleanup_and_logout(fl, h_session);
}

unsafe fn bootstrap_and_login() -> (*const CK_FUNCTION_LIST, CK_SESSION_HANDLE) {
    section("Bootstrap: Obtain Dispatch Table & Login");
    let mut fl_ptr: *const CK_FUNCTION_LIST = ptr::null();
    ck_ok(C_GetFunctionList(&mut fl_ptr), "C_GetFunctionList");
    let fl = &*fl_ptr;
    info("PKCS#11 Version", &format!("{}.{}", fl.version.major, fl.version.minor));

    let rv = p11!(fl, C_Initialize, ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED, "C_Initialize failed");

    let mut slot_count: CK_ULONG = 0;
    ck_ok(p11!(fl, C_GetSlotList, CK_TRUE, ptr::null_mut(), &mut slot_count), "C_GetSlotList");
    let mut slots = vec![0u64; slot_count as usize];
    ck_ok(p11!(fl, C_GetSlotList, CK_TRUE, slots.as_mut_ptr(), &mut slot_count), "C_GetSlotList");

    let mut h_session: CK_SESSION_HANDLE = 0;
    ck_ok(p11!(fl, C_OpenSession, slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
        ptr::null_mut(), None, &mut h_session), "C_OpenSession");
    ck_ok(p11!(fl, C_Login, h_session, CKU_USER, PIN.as_ptr(), PIN.len() as CK_ULONG), "C_Login");

    ok("Successfully established an authenticated R/W session");
    (fl_ptr, h_session)
}

unsafe fn cleanup_and_logout(fl: &CK_FUNCTION_LIST, h_session: CK_SESSION_HANDLE) {
    section("Teardown: Logout & Finalize");
    ck_ok(p11!(fl, C_Logout, h_session), "C_Logout");
    ck_ok(p11!(fl, C_CloseSession, h_session), "C_CloseSession");
    ck_ok(p11!(fl, C_Finalize, ptr::null_mut()), "C_Finalize");
    ok("Session closed, library finalised securely.");
}

unsafe fn demo_secure_randomness(fl: &CK_FUNCTION_LIST, h_session: CK_SESSION_HANDLE) {
    section("Scenario 1: Secure Randomness (Session/Nonce Generation)");
    let mut rand_buf = [0u8; 32];
    ck_ok(p11!(fl, C_GenerateRandom, h_session, rand_buf.as_mut_ptr(), 32), "C_GenerateRandom");
    info("Generated Secure Session ID", &hex(&rand_buf));
    ok("Randomness generated directly from HSM/Provider entropy pool.");
}

unsafe fn demo_symmetric_aead(fl: &CK_FUNCTION_LIST, h_session: CK_SESSION_HANDLE) {
    section("Scenario 2: Symmetric Encrypted Storage (AES-GCM)");

    let key_len: CK_ULONG = 32;
    let mut aes_attrs = [CK_ATTRIBUTE {
        r#type:     CKA_VALUE_LEN,
        pValue:     &key_len as *const CK_ULONG as *mut c_void,
        ulValueLen: 8,
    }];
    let mech_aes_gen = CK_MECHANISM { mechanism: CKM_AES_KEY_GEN, pParameter: ptr::null(), ulParameterLen: 0 };
    let mut h_aes: CK_OBJECT_HANDLE = 0;
    ck_ok(p11!(fl, C_GenerateKey, h_session, &mech_aes_gen, aes_attrs.as_mut_ptr(), 1, &mut h_aes), "Generate AES-256 DEK");

    let pii_record = b"{\"ssn\": \"123-45-6789\", \"dob\": \"1980-01-01\"}";
    let db_row_id  = b"row_id=987654";
    let iv         = [0x12u8; 12];

    let gcm_params = GcmParams {
        pIv:      iv.as_ptr(), ulIvLen:  iv.len() as u64, ulIvBits: (iv.len() * 8) as u64,
        pAAD:     db_row_id.as_ptr(), ulAADLen: db_row_id.len() as u64, ulTagBits: 128,
    };
    let mech_gcm = CK_MECHANISM {
        mechanism:      CKM_AES_GCM,
        pParameter:     &gcm_params as *const GcmParams as *mut c_void,
        ulParameterLen: std::mem::size_of::<GcmParams>() as CK_ULONG,
    };

    ck_ok(p11!(fl, C_EncryptInit, h_session, &mech_gcm, h_aes), "Initialize AES-GCM Encryption");
    let mut ciphertext = vec![0u8; pii_record.len() + 16];
    let mut ct_len = ciphertext.len() as CK_ULONG;
    ck_ok(p11!(fl, C_Encrypt, h_session, pii_record.as_ptr(), pii_record.len() as CK_ULONG, ciphertext.as_mut_ptr(), &mut ct_len), "Encrypt PII Record");
    ciphertext.truncate(ct_len as usize);
    info("Encrypted Database Payload (CT + Tag)", &hex(&ciphertext));

    ck_ok(p11!(fl, C_DecryptInit, h_session, &mech_gcm, h_aes), "Initialize AES-GCM Decryption");
    let mut plaintext = vec![0u8; ciphertext.len()];
    let mut pt_len = plaintext.len() as CK_ULONG;
    ck_ok(p11!(fl, C_Decrypt, h_session, ciphertext.as_ptr(), ct_len, plaintext.as_mut_ptr(), &mut pt_len), "Decrypt PII Record");
    plaintext.truncate(pt_len as usize);

    assert_eq!(plaintext, pii_record, "Decrypted record does not match!");
    ok("Successfully encrypted and authenticated database record.");
    ck_ok(p11!(fl, C_DestroyObject, h_session, h_aes), "Destroy AES DEK");
}

unsafe fn demo_document_signing_pki(fl: &CK_FUNCTION_LIST, h_session: CK_SESSION_HANDLE) {
    section("Scenario 3: Document Signing PKI (ECDSA P-256)");

    let p256_oid = [0x06u8, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let mut pub_attrs = [CK_ATTRIBUTE {
        r#type:     CKA_EC_PARAMS,
        pValue:     p256_oid.as_ptr() as *mut c_void,
        ulValueLen: p256_oid.len() as CK_ULONG,
    }];
    let mut priv_attrs: [CK_ATTRIBUTE; 0] = [];
    let mech_gen = CK_MECHANISM { mechanism: CKM_EC_KEY_PAIR_GEN, pParameter: ptr::null(), ulParameterLen: 0 };

    let mut h_pub: CK_OBJECT_HANDLE = 0;
    let mut h_priv: CK_OBJECT_HANDLE = 0;
    ck_ok(p11!(fl, C_GenerateKeyPair, h_session, &mech_gen, pub_attrs.as_mut_ptr(), 1, priv_attrs.as_mut_ptr(), 0, &mut h_pub, &mut h_priv), "Generate ECDSA Keypair");

    let document_hash = b"8e35c2cd3bf6641bdb0e2050b76932cbb2e6034a0ddfad1d928b0488"; // Hash to sign
    let mech_ecdsa = CK_MECHANISM { mechanism: CKM_ECDSA, pParameter: ptr::null(), ulParameterLen: 0 };

    ck_ok(p11!(fl, C_SignInit, h_session, &mech_ecdsa, h_priv), "Initialize ECDSA Signature");
    let mut signature = vec![0u8; 72];
    let mut sig_len = 72 as CK_ULONG;
    ck_ok(p11!(fl, C_Sign, h_session, document_hash.as_ptr(), document_hash.len() as CK_ULONG, signature.as_mut_ptr(), &mut sig_len), "Sign Document Hash");
    signature.truncate(sig_len as usize);
    info("Document Signature (DER)", &hex(&signature));

    ck_ok(p11!(fl, C_VerifyInit, h_session, &mech_ecdsa, h_pub), "Initialize ECDSA Verification");
    ck_ok(p11!(fl, C_Verify, h_session, document_hash.as_ptr(), document_hash.len() as CK_ULONG, signature.as_ptr(), sig_len), "Verify Document Signature");
    ok("Document signature verified successfully.");

    ck_ok(p11!(fl, C_DestroyObject, h_session, h_priv), "Destroy ECDSA Private Key");
    ck_ok(p11!(fl, C_DestroyObject, h_session, h_pub), "Destroy ECDSA Public Key");
}

unsafe fn demo_envelope_encryption(fl: &CK_FUNCTION_LIST, h_session: CK_SESSION_HANDLE) {
    section("Scenario 4: Envelope Encryption (AES Key Wrap)");

    let val_true = [CK_TRUE];

    // 1. Generate the Master KEK (Key Encrypting Key)
    let key_len: CK_ULONG = 32;
    let mut kek_attrs = [
        CK_ATTRIBUTE { r#type: CKA_VALUE_LEN, pValue: &key_len as *const CK_ULONG as *mut c_void, ulValueLen: 8 },
        CK_ATTRIBUTE { r#type: CKA_WRAP, pValue: val_true.as_ptr() as *mut c_void, ulValueLen: 1 },
        CK_ATTRIBUTE { r#type: CKA_UNWRAP, pValue: val_true.as_ptr() as *mut c_void, ulValueLen: 1 },
    ];
    let mech_aes_gen = CK_MECHANISM { mechanism: CKM_AES_KEY_GEN, pParameter: ptr::null(), ulParameterLen: 0 };
    let mut h_kek: CK_OBJECT_HANDLE = 0;
    ck_ok(p11!(fl, C_GenerateKey, h_session, &mech_aes_gen, kek_attrs.as_mut_ptr(), 3, &mut h_kek), "Generate Master KEK");

    // 2. Generate the ephemeral DEK (Data Encrypting Key)
    let mut dek_attrs = [
        CK_ATTRIBUTE { r#type: CKA_VALUE_LEN, pValue: &key_len as *const CK_ULONG as *mut c_void, ulValueLen: 8 },
        CK_ATTRIBUTE { r#type: CKA_EXTRACTABLE, pValue: val_true.as_ptr() as *mut c_void, ulValueLen: 1 },
    ];
    let mut h_dek: CK_OBJECT_HANDLE = 0;
    ck_ok(p11!(fl, C_GenerateKey, h_session, &mech_aes_gen, dek_attrs.as_mut_ptr(), 2, &mut h_dek), "Generate Ephemeral DEK");

    // 3. Wrap DEK with KEK
    let mech_wrap = CK_MECHANISM { mechanism: CKM_AES_KEY_WRAP, pParameter: ptr::null(), ulParameterLen: 0 };
    let mut wrapped_key = vec![0u8; 64];
    let mut wrapped_len = 64 as CK_ULONG;
    ck_ok(p11!(fl, C_WrapKey, h_session, &mech_wrap, h_kek, h_dek, wrapped_key.as_mut_ptr(), &mut wrapped_len), "Wrap DEK with Master KEK");
    wrapped_key.truncate(wrapped_len as usize);
    info("Wrapped DEK Blob (RFC 3394)", &hex(&wrapped_key));

    // 4. Unwrap to a new handle
    let mut unwrap_attrs = [
        CK_ATTRIBUTE { r#type: CKA_CLASS, pValue: &(CKO_SECRET_KEY as CK_ULONG) as *const CK_ULONG as *mut c_void, ulValueLen: 8 },
        CK_ATTRIBUTE { r#type: CKA_KEY_TYPE, pValue: &(CKK_AES as CK_ULONG) as *const CK_ULONG as *mut c_void, ulValueLen: 8 },
    ];
    let mut h_unwrapped_dek: CK_OBJECT_HANDLE = 0;
    ck_ok(p11!(fl, C_UnwrapKey, h_session, &mech_wrap, h_kek, wrapped_key.as_ptr(), wrapped_len, unwrap_attrs.as_mut_ptr(), 2, &mut h_unwrapped_dek), "Unwrap Blob to New DEK Handle");
    ok("Successfully executed Envelope Encryption (Wrap/Unwrap).");

    ck_ok(p11!(fl, C_DestroyObject, h_session, h_kek), "Destroy Master KEK");
    ck_ok(p11!(fl, C_DestroyObject, h_session, h_dek), "Destroy Original DEK");
    ck_ok(p11!(fl, C_DestroyObject, h_session, h_unwrapped_dek), "Destroy Unwrapped DEK");
}

unsafe fn demo_secure_hashing(fl: &CK_FUNCTION_LIST, h_session: CK_SESSION_HANDLE) {
    section("Scenario 5: Secure Hashing (SHA-256)");

    let mech_sha256 = CK_MECHANISM { mechanism: CKM_SHA256, pParameter: ptr::null(), ulParameterLen: 0 };
    ck_ok(p11!(fl, C_DigestInit, h_session, &mech_sha256), "Initialize SHA-256 Digest");

    let file_chunks: &[&[u8]] = &[
        b"Business Contract Version 1.0\n",
        b"Section 1: Confidentiality...\n",
        b"Section 2: Terms and Conditions...\n",
    ];

    for (i, chunk) in file_chunks.iter().enumerate() {
        ck_ok(p11!(fl, C_DigestUpdate, h_session, chunk.as_ptr(), chunk.len() as CK_ULONG), &format!("DigestUpdate (Chunk {})", i + 1));
    }

    let mut digest_buf = [0u8; 32];
    let mut digest_len: CK_ULONG = 32;
    ck_ok(p11!(fl, C_DigestFinal, h_session, digest_buf.as_mut_ptr(), &mut digest_len), "Finalize Digest");

    info("Document SHA-256 Hash", &hex(&digest_buf));
    ok("File integrity hash computed successfully using streaming chunks.");
}
