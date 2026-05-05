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

use openssl::hash::{hash, MessageDigest};
use parsec_client::core::basic_client::BasicClient;
use parsec_client::core::interface::operations::psa_algorithm::{
    Algorithm, AsymmetricSignature, Hash, SignHash,
};
use parsec_client::core::interface::operations::psa_key_attributes::{
    Attributes, EccFamily, Lifetime, Policy, Type, UsageFlags,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        std::process::exit(1);
    }

    let client = BasicClient::new(Some("parsec-cli".to_string()))
        .expect("failed to connect to Parsec service (is it running? check PARSEC_SERVICE_ENDPOINT)");

    match args[1].as_str() {
        "keygen"  => cmd_keygen(&client, &args[2..]),
        "list"    => cmd_list(&client),
        "sign"    => cmd_sign(&client, &args[2..]),
        "verify"  => cmd_verify(&client, &args[2..]),
        "export"  => cmd_export(&client, &args[2..]),
        "destroy" => cmd_destroy(&client, &args[2..]),
        "random"  => cmd_random(&client, &args[2..]),
        cmd => {
            eprintln!("unknown command: {cmd}");
            usage();
            std::process::exit(1);
        }
    }
}

// ── keygen ────────────────────────────────────────────────────────────────────

fn cmd_keygen(client: &BasicClient, args: &[String]) {
    let name = require_arg(args, 0, "keygen <name>");
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

    client.psa_generate_key(name, attrs).expect("keygen failed");
    println!("generated: {name}");
}

// ── list ──────────────────────────────────────────────────────────────────────

fn cmd_list(client: &BasicClient) {
    let keys = client.list_keys().expect("list_keys failed");
    if keys.is_empty() {
        println!("(no keys)");
    } else {
        for k in &keys {
            println!("{}", k.name);
        }
    }
}

// ── sign ──────────────────────────────────────────────────────────────────────

fn cmd_sign(client: &BasicClient, args: &[String]) {
    let name = require_arg(args, 0, "sign <name> <message>");
    let msg  = require_arg(args, 1, "sign <name> <message>").as_bytes();
    let alg  = ecdsa_sha256();
    let digest = hash(MessageDigest::sha256(), msg).expect("sha256 failed");
    let sig = client.psa_sign_hash(name, &digest, alg).expect("sign failed");
    println!("{}", hex(&sig));
}

// ── verify ────────────────────────────────────────────────────────────────────

fn cmd_verify(client: &BasicClient, args: &[String]) {
    let name    = require_arg(args, 0, "verify <name> <message> <sig-hex>");
    let msg     = require_arg(args, 1, "verify <name> <message> <sig-hex>").as_bytes();
    let sig_hex = require_arg(args, 2, "verify <name> <message> <sig-hex>");
    let alg     = ecdsa_sha256();
    let sig     = unhex(sig_hex).expect("invalid hex signature");
    let digest  = hash(MessageDigest::sha256(), msg).expect("sha256 failed");
    client.psa_verify_hash(name, &digest, alg, &sig).expect("verify failed");
    println!("ok");
}

// ── export ────────────────────────────────────────────────────────────────────

fn cmd_export(client: &BasicClient, args: &[String]) {
    let name = require_arg(args, 0, "export <name>");
    let pub_key = client.psa_export_public_key(name).expect("export failed");
    println!("{}", hex(&pub_key));
}

// ── destroy ───────────────────────────────────────────────────────────────────

fn cmd_destroy(client: &BasicClient, args: &[String]) {
    let name = require_arg(args, 0, "destroy <name>");
    client.psa_destroy_key(name).expect("destroy failed");
    println!("destroyed: {name}");
}

// ── random ────────────────────────────────────────────────────────────────────

fn cmd_random(client: &BasicClient, args: &[String]) {
    let n_str = require_arg(args, 0, "random <n>");
    let n: usize = n_str.parse().expect("n must be a positive integer");
    let bytes = client.psa_generate_random(n).expect("random failed");
    println!("{}", hex(&bytes));
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn ecdsa_sha256() -> AsymmetricSignature {
    AsymmetricSignature::Ecdsa {
        hash_alg: SignHash::Specific(Hash::Sha256),
    }
}

fn require_arg<'a>(args: &'a [String], idx: usize, usage_hint: &str) -> &'a str {
    args.get(idx).map(|s| s.as_str()).unwrap_or_else(|| {
        eprintln!("usage: {usage_hint}");
        std::process::exit(1);
    })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn usage() {
    eprintln!(concat!(
        "parsec_client <command> [args]\n",
        "\n",
        "commands:\n",
        "  keygen  <name>                    generate P-256 signing key\n",
        "  list                              list all keys\n",
        "  sign    <name> <message>          sign message, print hex sig\n",
        "  verify  <name> <message> <sig>    verify hex sig\n",
        "  export  <name>                    print SPKI DER as hex\n",
        "  destroy <name>                    delete key\n",
        "  random  <n>                       print n random bytes as hex",
    ));
}
