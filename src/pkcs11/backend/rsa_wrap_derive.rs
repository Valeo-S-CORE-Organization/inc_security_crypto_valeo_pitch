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
use zeroize::Zeroizing;

use super::*;

pub fn rsa_encrypt(slot_id: CK_SLOT_ID, mechanism: CK_MECHANISM_TYPE, key: &KeyObject, plaintext: &[u8]) -> Result<Vec<u8>> {
    let e = eng(slot_id)?;
    match mechanism {
        CKM_RSA_PKCS => e.rsa_pkcs1_encrypt(&key.key_ref, plaintext).map_err(Pkcs11Error::from),
        CKM_RSA_PKCS_OAEP => e.rsa_oaep_encrypt(&key.key_ref, plaintext).map_err(Pkcs11Error::from),
        _ => Err(Pkcs11Error::InvalidMechanism),
    }
}

pub fn rsa_decrypt(slot_id: CK_SLOT_ID, mechanism: CK_MECHANISM_TYPE, key: &KeyObject, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let e = eng(slot_id)?;
    match mechanism {
        CKM_RSA_PKCS => e.rsa_pkcs1_decrypt(&key.key_ref, ciphertext).map_err(Pkcs11Error::from),
        CKM_RSA_PKCS_OAEP => e.rsa_oaep_decrypt(&key.key_ref, ciphertext).map_err(Pkcs11Error::from),
        _ => Err(Pkcs11Error::InvalidMechanism),
    }
}

pub fn aes_wrap_key(slot_id: CK_SLOT_ID, wrapping_key: &KeyObject, target_key: &KeyObject) -> Result<Vec<u8>> {
    let e = eng(slot_id)?;
    e.aes_key_wrap(&wrapping_key.key_ref, &target_key.key_ref).map_err(Pkcs11Error::from)
}

pub fn aes_wrap_key_refs(
    slot_id: CK_SLOT_ID,
    wrapping_ref: &crate::traits::EngineKeyRef,
    target_ref: &crate::traits::EngineKeyRef,
) -> Result<Vec<u8>> {
    let e = eng(slot_id)?;
    e.aes_key_wrap(wrapping_ref, target_ref).map_err(Pkcs11Error::from)
}

pub fn aes_unwrap_key(
    slot_id: CK_SLOT_ID,
    unwrapping_key: &KeyObject,
    wrapped_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let e = eng(slot_id)?;
    e.aes_key_unwrap(&unwrapping_key.key_ref, wrapped_key).map_err(Pkcs11Error::from)
}

pub fn hkdf_derive(
    slot_id: CK_SLOT_ID,
    base_key: &KeyObject,
    hash: crate::types::HashAlgorithm,
    salt: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let e = eng(slot_id)?;
    e.hkdf_derive(hash, &base_key.key_ref, salt, info, okm_len).map_err(Pkcs11Error::from)
}
