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

// Parsec client demo — connects to a live Parsec service.
//
// Start the service first (or use service_demo.rs which does it automatically):
//   PARSEC_SERVICE_ENDPOINT=unix:/home/omar/.pkcs11-engine/parsec/run/parsec.sock \
//   cargo run --example parsec_client_demo

use openssl::hash::{hash, MessageDigest};
use parsec_client::core::basic_client::BasicClient;
use parsec_client::core::interface::operations::psa_algorithm::{
    Algorithm, AsymmetricSignature, Hash, SignHash,
};
use parsec_client::core::interface::operations::psa_key_attributes::{
    Attributes, EccFamily, Lifetime, Policy, Type, UsageFlags,
};

const KEY_NAME: &str = "demo-ecc-signing-key";

fn main() {
    let client = BasicClient::new(Some("parsec-client-demo".to_string()))
        .expect("failed to connect to Parsec service");

    let _ = client.psa_destroy_key(KEY_NAME);

    // 1. Generate P-256 persistent signing key
    let mut usage = UsageFlags::default();
    usage
        .set_sign_hash()
        .set_verify_hash()
        .set_sign_message()
        .set_verify_message();

    let attrs = Attributes {
        lifetime: Lifetime::Persistent,
        key_type: Type::EccKeyPair {
            curve_family: EccFamily::SecpR1,
        },
        bits: 256,
        policy: Policy {
            usage_flags: usage,
            permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: SignHash::Specific(Hash::Sha256),
            }),
        },
    };

    client.psa_generate_key(KEY_NAME, attrs).expect("keygen failed");
    println!("[1] key '{}' generated (P-256, persistent)", KEY_NAME);

    // 2. Sign — PKCS#11 provider exposes PsaSignHash, not PsaSignMessage
    let message = b"hello from pkcs11-engine via parsec";
    let digest = hash(MessageDigest::sha256(), message).expect("sha256 failed");
    let alg = AsymmetricSignature::Ecdsa {
        hash_alg: SignHash::Specific(Hash::Sha256),
    };

    let signature = client
        .psa_sign_hash(KEY_NAME, &digest, alg)
        .expect("sign failed");
    println!("[2] signature ({} bytes): {}", signature.len(), hex(&signature));

    // 3. Verify
    client
        .psa_verify_hash(KEY_NAME, &digest, alg, &signature)
        .expect("verify failed");
    println!("[3] signature verified OK");

    // 4. Export public key (SPKI DER)
    let pub_key = client
        .psa_export_public_key(KEY_NAME)
        .expect("export public key failed");
    println!(
        "[4] public key ({} bytes SPKI DER): {}...",
        pub_key.len(),
        hex(&pub_key[..16])
    );

    // 5. Random bytes
    let rand = client.psa_generate_random(32).expect("random failed");
    println!("[5] random (32 bytes): {}", hex(&rand));

    // 6. Cleanup
    client.psa_destroy_key(KEY_NAME).expect("destroy failed");
    println!("[6] key destroyed");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join("")
}
