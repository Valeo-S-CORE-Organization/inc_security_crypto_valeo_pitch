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

//! Logging smoke tests.
//!
//! These tests do not assert on concrete log output text (to avoid brittleness).
//! They ensure instrumented code paths execute and PKCS#11 behavior stays stable.

mod common;

use cryptoki::pkcs11::constants::*;
use cryptoki::pkcs11::types::*;
use cryptoki::pkcs11::{C_Finalize, C_Initialize};
use std::ptr;
use std::sync::OnceLock;

use std::env;
use std::path::PathBuf;
use std::process::Command;

static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();

fn serial_lock() -> std::sync::MutexGuard<'static, ()> {
    LOCK.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

unsafe fn ensure_finalized() {
    let rv = C_Finalize(ptr::null_mut());
    assert!(rv == CKR_OK || rv == CKR_CRYPTOKI_NOT_INITIALIZED,
        "ensure_finalized: unexpected rv {rv:#010x}");
}

#[test]
fn test_logging_output_captured() {
    // If we are the child, do the actual FFI calls and exit successfully.
    if env::var("_PKCS11_LOG_TEST_CHILD").is_ok() {
        let _g = serial_lock();
        unsafe {
            ensure_finalized();
            // Trigger C_Initialize to set up the logger.
            let _ = C_Initialize(ptr::null_mut());
            
            // Trigger a known WARN-level log by calling C_Finalize when already finalized.
            let _ = C_Finalize(ptr::null_mut());
            let rv = C_Finalize(ptr::null_mut());
            assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED);
        }
        std::process::exit(0);
    }

    // We are the parent. Prepare a valid config file in a dedicated directory.
    let config_content = r#"{
    "appId": "TEST",
    "appDesc": "Rust test scenarios",
    "logMode": "kConsole",
    "logLevel": "kVerbose",
    "logLevelThresholdConsole": "kInfo"
}"#;
    let base_dir = env::var("TEST_TMPDIR").map(PathBuf::from).unwrap_or_else(|_| env::current_dir().unwrap());
    let temp_dir = base_dir.join("test_log_dir");
    std::fs::create_dir_all(&temp_dir).expect("Failed to create temp log dir");
    let config_path = temp_dir.join("logging.json");
    std::fs::write(&config_path, config_content).expect("Failed to write temp config");

    let exe = env::current_exe().expect("Failed to get current executable");
    
    let output = Command::new(&exe)
        .arg("test_logging_output_captured")
        .arg("--exact")
        .arg("--nocapture")
        .env("_PKCS11_LOG_TEST_CHILD", "1")
        .env("PKCS11_LOG_CONFIG", &config_path)
        .env("TEST_TMPDIR", &base_dir) // Ensure child sees the same tmpdir if needed
        .output()
        .expect("Failed to execute child process");

    // Clean up
    let _ = std::fs::remove_dir_all(&temp_dir);

    assert!(output.status.success(), "Child process failed: {:?}", output);
    
    // Combine stdout and stderr
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    // 1. Verify that the config WAS loaded (no fallback error)
    assert!(!combined.contains("Failed to load configuration files"), 
        "Logger fell back to console mode unexpectedly! It failed to load the config file at {:?}.\nOutput:\n{}", 
        config_path, combined);

    // 2. Verify our expected FFI logs are present
    assert!(combined.contains("C_Finalize called while not initialized"), 
        "Missing expected warning log in:\n{}", combined);
}

#[test]
fn logging_smoke_happy_path() {
    let _g = serial_lock();
    unsafe {
        ensure_finalized();

        let rv = C_Initialize(ptr::null_mut());
        assert_eq!(rv, CKR_OK, "C_Initialize failed: {rv:#010x}");

        let fl = common::fn_list();
        let h = common::open_session(fl);

        let mut out = [0u8; 32];
        let rv = p11!(fl, C_GenerateRandom, h, out.as_mut_ptr(), out.len() as CK_ULONG);
        assert_eq!(rv, CKR_OK, "C_GenerateRandom failed: {rv:#010x}");

        let rv = p11!(fl, C_CloseSession, h);
        assert_eq!(rv, CKR_OK, "C_CloseSession failed: {rv:#010x}");

        let rv = C_Finalize(ptr::null_mut());
        assert_eq!(rv, CKR_OK, "C_Finalize failed: {rv:#010x}");
    }
}

#[test]
fn logging_smoke_error_path_contract() {
    let _g = serial_lock();
    unsafe {
        ensure_finalized();

        let rv = C_Finalize(ptr::null_mut());
        assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED,
            "finalize-when-not-initialized contract changed: {rv:#010x}");

        let rv = C_Initialize(ptr::null_mut());
        assert_eq!(rv, CKR_OK, "C_Initialize failed: {rv:#010x}");

        let rv2 = C_Initialize(ptr::null_mut());
        assert_eq!(rv2, CKR_CRYPTOKI_ALREADY_INITIALIZED,
            "double init contract changed: {rv2:#010x}");

        ensure_finalized();
    }
}
