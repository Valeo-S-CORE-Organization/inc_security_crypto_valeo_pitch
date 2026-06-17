/**
 * @file demo.cpp
 * @brief Demonstration program for the PKCS#11 C++ wrapper.
 *
 * Build (after `cargo build --release`):
 * @code{.sh}
 *   cd cpp && mkdir -p build && cd build
 *   cmake .. && make
 *   ./demo
 * @endcode
 */

#include "pkcs11_cpp.hpp"

#include <iostream>
#include <iomanip>
#include <cassert>
#include <sstream>

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

static std::string toHexStr(const std::vector<uint8_t>& v) {
    std::ostringstream oss;
    for (auto b : v)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return oss.str();
}

static void printResult(const char* name, bool ok) {
    std::cout << "  [" << (ok ? "PASS" : "FAIL") << "] " << name << "\n";
}

// ---------------------------------------------------------------------------
// Demo sections
// ---------------------------------------------------------------------------

void demoRsaSignVerify(pkcs11::Session& session) {
    std::cout << "\n--- RSA-2048 Sign / Verify ---\n";
    auto [hPub, hPriv] = session.generateRsaKeyPair(2048);
    std::cout << "  Generated RSA-2048 key pair (pub=" << hPub
              << ", priv=" << hPriv << ")\n";

    std::vector<uint8_t> msg = {'H','e','l','l','o',' ','W','o','r','l','d'};
    auto sig = session.sign(CKM_SHA256_RSA_PKCS, hPriv, msg);
    std::cout << "  Signature (" << sig.size() << " bytes): "
              << toHexStr(sig).substr(0, 32) << "...\n";

    bool verified = false;
    try {
        session.verify(CKM_SHA256_RSA_PKCS, hPub, msg, sig);
        verified = true;
    } catch (const pkcs11::Pkcs11Exception& e) {
        std::cerr << "  Verify exception: " << e.what() << "\n";
    }
    printResult("RSA sign+verify", verified);

    // Tamper test
    auto tampered = sig;
    tampered[0] ^= 0xFF;
    bool tamperRejected = false;
    try {
        session.verify(CKM_SHA256_RSA_PKCS, hPub, msg, tampered);
    } catch (const pkcs11::Pkcs11Exception& e) {
        tamperRejected = (e.rv() == CKR_SIGNATURE_INVALID);
    }
    printResult("Tampered signature rejected", tamperRejected);
}

void demoRsaPssSignVerify(pkcs11::Session& session) {
    std::cout << "\n--- RSA-PSS Sign / Verify ---\n";
    auto [hPub, hPriv] = session.generateRsaKeyPair(2048);

    std::vector<uint8_t> msg = {'P','S','S',' ','t','e','s','t'};
    auto sig = session.sign(CKM_SHA256_RSA_PKCS_PSS, hPriv, msg);
    std::cout << "  PSS Signature (" << sig.size() << " bytes)\n";

    bool verified = false;
    try {
        session.verify(CKM_SHA256_RSA_PKCS_PSS, hPub, msg, sig);
        verified = true;
    } catch (...) {}
    printResult("RSA-PSS sign+verify", verified);
}

void demoRsaOaep(pkcs11::Session& session) {
    std::cout << "\n--- RSA-OAEP Encrypt / Decrypt ---\n";
    auto [hPub, hPriv] = session.generateRsaKeyPair(2048);

    std::vector<uint8_t> secret = {'s','e','c','r','e','t'};
    auto ct = session.encryptRsaOaep(hPub, secret);
    std::cout << "  OAEP ciphertext (" << ct.size() << " bytes)\n";

    auto pt = session.decryptRsaOaep(hPriv, ct);
    bool ok = (pt == secret);
    printResult("RSA-OAEP encrypt+decrypt", ok);
}

void demoEcSignVerify(pkcs11::Session& session) {
    std::cout << "\n--- EC P-256 Sign / Verify ---\n";
    auto [hPub, hPriv] = session.generateEcKeyPair();
    std::cout << "  Generated EC P-256 key pair (pub=" << hPub
              << ", priv=" << hPriv << ")\n";

    std::vector<uint8_t> msg(32, 0xAB);
    auto sig = session.sign(CKM_ECDSA, hPriv, msg);
    std::cout << "  Signature (" << sig.size() << " bytes): "
              << toHexStr(sig).substr(0, 32) << "...\n";

    bool verified = false;
    try {
        session.verify(CKM_ECDSA, hPub, msg, sig);
        verified = true;
    } catch (...) {}
    printResult("EC sign+verify", verified);
}

void demoAesGcm(pkcs11::Session& session) {
    std::cout << "\n--- AES-256-GCM Encrypt / Decrypt ---\n";
    CK_OBJECT_HANDLE hKey = session.generateAesKey(32);
    std::cout << "  Generated AES-256 key (handle=" << hKey << ")\n";

    std::vector<uint8_t> iv(12, 0x01);
    std::vector<uint8_t> plain = {'S','e','c','r','e','t',' ','d','a','t','a'};

    auto ct = session.encryptAesGcm(hKey, iv, plain);
    std::cout << "  Ciphertext+tag (" << ct.size() << " bytes): "
              << toHexStr(ct).substr(0, 40) << "...\n";

    auto recovered = session.decryptAesGcm(hKey, iv, ct);
    bool ok = (recovered == plain);
    printResult("AES-GCM encrypt+decrypt", ok);

    // Authentication check: corrupt tag
    auto corrupted = ct;
    corrupted.back() ^= 0xFF;
    bool authFailed = false;
    try {
        session.decryptAesGcm(hKey, iv, corrupted);
    } catch (const pkcs11::Pkcs11Exception& e) {
        authFailed = (e.rv() == CKR_ENCRYPTED_DATA_INVALID);
    }
    printResult("AES-GCM tampered tag rejected", authFailed);
}

void demoAesCbc(pkcs11::Session& session) {
    std::cout << "\n--- AES-256-CBC Encrypt / Decrypt ---\n";
    CK_OBJECT_HANDLE hKey = session.generateAesKey(32);

    std::vector<uint8_t> iv(16, 0x01);
    std::vector<uint8_t> plain = {'H','e','l','l','o',' ','C','B','C','!','!','!'};

    auto ct = session.encryptAesCbc(hKey, iv, plain);
    std::cout << "  Ciphertext (" << ct.size() << " bytes): "
              << toHexStr(ct) << "\n";

    auto recovered = session.decryptAesCbc(hKey, iv, ct);
    bool ok = (recovered == plain);
    printResult("AES-CBC encrypt+decrypt", ok);
}

void demoDigest(pkcs11::Session& session) {
    std::cout << "\n--- SHA-256 Digest ---\n";
    std::vector<uint8_t> data = {'a','b','c'};
    auto hash = session.digest(CKM_SHA256, data);
    std::cout << "  SHA-256(\"abc\"): " << toHexStr(hash) << "\n";
    // First byte of SHA-256("abc") is 0xba
    bool ok = (hash.size() == 32 && hash[0] == 0xba);
    printResult("SHA-256 known vector", ok);
}

void demoRandom(pkcs11::Session& session) {
    std::cout << "\n--- Random Generation ---\n";
    auto rnd = session.generateRandom(32);
    bool nonZero = false;
    for (auto b : rnd) if (b) { nonZero = true; break; }
    printResult("32 bytes random (non-zero)", nonZero);
    std::cout << "  " << toHexStr(rnd) << "\n";
}

void demoEdDsaSignVerify(pkcs11::Session& session) {
    std::cout << "\n--- EdDSA (Ed25519) Sign / Verify ---\n";
    auto [hPub, hPriv] = session.generateEdKeyPair();
    std::cout << "  Generated Ed25519 key pair (pub=" << hPub
              << ", priv=" << hPriv << ")\n";

    std::vector<uint8_t> msg = {'E','d','D','S','A',' ','t','e','s','t'};
    auto sig = session.sign(CKM_EDDSA, hPriv, msg);
    std::cout << "  Signature (" << sig.size() << " bytes): "
              << toHexStr(sig).substr(0, 32) << "...\n";

    bool verified = false;
    try {
        session.verify(CKM_EDDSA, hPub, msg, sig);
        verified = true;
    } catch (...) {}
    printResult("EdDSA sign+verify", verified);

    // Tamper test
    auto tampered = sig;
    tampered[0] ^= 0xFF;
    bool tamperRejected = false;
    try {
        session.verify(CKM_EDDSA, hPub, msg, tampered);
    } catch (const pkcs11::Pkcs11Exception& e) {
        tamperRejected = (e.rv() == CKR_SIGNATURE_INVALID);
    }
    printResult("EdDSA tampered signature rejected", tamperRejected);
}

void demoChaCha20Poly1305(pkcs11::Session& session) {
    std::cout << "\n--- ChaCha20-Poly1305 Encrypt / Decrypt ---\n";
    CK_OBJECT_HANDLE hKey = session.generateChaCha20Key();
    std::cout << "  Generated ChaCha20 key (handle=" << hKey << ")\n";

    std::vector<uint8_t> nonce(12, 0x42);
    std::vector<uint8_t> plain = {'C','h','a','C','h','a','2','0',' ','t','e','s','t'};

    auto ct = session.encryptChaCha20Poly1305(hKey, nonce, plain);
    std::cout << "  Ciphertext+tag (" << ct.size() << " bytes): "
              << toHexStr(ct).substr(0, 40) << "...\n";

    auto recovered = session.decryptChaCha20Poly1305(hKey, nonce, ct);
    bool ok = (recovered == plain);
    printResult("ChaCha20-Poly1305 encrypt+decrypt", ok);

    // Authentication check: corrupt tag
    auto corrupted = ct;
    corrupted.back() ^= 0xFF;
    bool authFailed = false;
    try {
        session.decryptChaCha20Poly1305(hKey, nonce, corrupted);
    } catch (const pkcs11::Pkcs11Exception&) {
        authFailed = true;
    }
    printResult("ChaCha20-Poly1305 tampered tag rejected", authFailed);
}

void demoSha3Digest(pkcs11::Session& session) {
    std::cout << "\n--- SHA-3 Digest ---\n";
    std::vector<uint8_t> data = {'a','b','c'};

    auto hash256 = session.digest(CKM_SHA3_256, data);
    bool ok256 = (hash256.size() == 32);
    printResult("SHA3-256 digest (32 bytes)", ok256);
    std::cout << "  SHA3-256(\"abc\"): " << toHexStr(hash256).substr(0, 32) << "...\n";

    auto hash384 = session.digest(CKM_SHA384, data);
    bool ok384 = (hash384.size() == 48);
    printResult("SHA-384 digest (48 bytes)", ok384);

    auto hash512 = session.digest(CKM_SHA512, data);
    bool ok512 = (hash512.size() == 64);
    printResult("SHA-512 digest (64 bytes)", ok512);
}

void demoFindObjects(pkcs11::Session& session) {
    std::cout << "\n--- FindObjects ---\n";
    auto all = session.findAllObjects();
    std::cout << "  Total objects in store: " << all.size() << "\n";
    printResult("FindObjects returned >0 results", !all.empty());

    // Find only private keys
    CK_ULONG classPriv = CKO_PRIVATE_KEY;
    auto privKeys = session.findObjects(CKA_CLASS, &classPriv, sizeof(classPriv));
    std::cout << "  Private key count: " << privKeys.size() << "\n";
    printResult("Private key filter works", !privKeys.empty());
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    std::cout << "============================\n";
    std::cout << "  PKCS#11 C++ Frontend Demo \n";
    std::cout << "============================\n";

    try {
        pkcs11::Library lib;

        auto slots = lib.getSlotList();
        std::cout << "\nFound " << slots.size() << " slot(s).\n";
        assert(!slots.empty() && "Expected at least one slot");

        pkcs11::Session session(lib, slots[0]);
        session.login("1234");
        std::cout << "Logged in successfully.\n";

        demoRsaSignVerify(session);
        demoRsaPssSignVerify(session);
        demoRsaOaep(session);
        demoEcSignVerify(session);
        demoEdDsaSignVerify(session);
        demoAesGcm(session);
        demoAesCbc(session);
        demoChaCha20Poly1305(session);
        demoDigest(session);
        demoSha3Digest(session);
        demoRandom(session);
        demoFindObjects(session);

        session.logout();
        std::cout << "\nAll demos completed.\n";

    } catch (const pkcs11::Pkcs11Exception& e) {
        std::cerr << "\nFATAL: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "\nFATAL: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
