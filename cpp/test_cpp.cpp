/**
 * @file test_cpp.cpp
 * @brief C++ unit tests for the PKCS#11 wrapper.
 *
 * Deliberately uses no external framework so it can be built with just
 * g++ and a linker path to the Rust shared library.
 *
 * Build:
 * @code{.sh}
 *   cd cpp && mkdir -p build && cd build
 *   cmake .. && make
 *   ./test_cpp
 * @endcode
 */

#include "pkcs11_cpp.hpp"

#include <iostream>
#include <cassert>
#include <functional>
#include <string>
#include <vector>
#include <stdexcept>

// ---------------------------------------------------------------------------
// Tiny test runner
// ---------------------------------------------------------------------------

struct TestCase {
    std::string name;
    std::function<void()> fn;
};

static int g_passed = 0;
static int g_failed = 0;

static void run(const TestCase& tc) {
    try {
        tc.fn();
        std::cout << "[PASS] " << tc.name << "\n";
        ++g_passed;
    } catch (const std::exception& e) {
        std::cout << "[FAIL] " << tc.name << " => " << e.what() << "\n";
        ++g_failed;
    }
}

#define ASSERT_EQ(a, b) \
    do { if ((a) != (b)) throw std::runtime_error(std::string("ASSERT_EQ failed at line ") + std::to_string(__LINE__)); } while(0)
#define ASSERT_TRUE(x) \
    do { if (!(x)) throw std::runtime_error(std::string("ASSERT_TRUE failed at line ") + std::to_string(__LINE__)); } while(0)
#define ASSERT_THROW(expr, rvCode) \
    do { \
        bool caught_ = false; \
        try { expr; } \
        catch (const pkcs11::Pkcs11Exception& _e) { \
            if (_e.rv() != (rvCode)) \
                throw std::runtime_error(std::string("Expected CKR 0x") + std::to_string(rvCode) + " got 0x" + std::to_string(_e.rv())); \
            caught_ = true; \
        } \
        if (!caught_) throw std::runtime_error("Expected exception not thrown"); \
    } while(0)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

static pkcs11::Library* g_lib = nullptr;

static pkcs11::Session makeSession() {
    return pkcs11::Session(*g_lib, 0, true);
}

static pkcs11::Session makeLoggedInSession() {
    auto s = makeSession();
    s.login("1234");
    return s;
}

// ---------------------------------------------------------------------------
// Tests: Library
// ---------------------------------------------------------------------------

void test_library_init() {
    pkcs11::Library lib2;    // double-init accepted silently
}

void test_slot_list_non_empty() {
    auto slots = g_lib->getSlotList();
    ASSERT_TRUE(!slots.empty());
    ASSERT_EQ(slots[0], (CK_SLOT_ID)0);
}

// ---------------------------------------------------------------------------
// Tests: Session
// ---------------------------------------------------------------------------

void test_open_close_session() {
    auto s = makeSession();
}

void test_login_logout() {
    auto s = makeLoggedInSession();
    s.logout();
}

void test_wrong_pin() {
    auto s = makeSession();
    ASSERT_THROW(s.login("wrong"), CKR_PIN_INCORRECT);
}

void test_double_login() {
    auto s = makeLoggedInSession();
    ASSERT_THROW(s.login("1234"), CKR_USER_ALREADY_LOGGED_IN);
}

// ---------------------------------------------------------------------------
// Tests: RSA
// ---------------------------------------------------------------------------

void test_rsa_keygen() {
    auto s = makeLoggedInSession();
    auto [hPub, hPriv] = s.generateRsaKeyPair(2048);
    ASSERT_TRUE(hPub  != 0);
    ASSERT_TRUE(hPriv != 0);
    ASSERT_TRUE(hPub  != hPriv);
}

void test_rsa_sign_verify() {
    auto s = makeLoggedInSession();
    auto [hPub, hPriv] = s.generateRsaKeyPair(2048);
    std::vector<uint8_t> msg = {1,2,3,4,5};
    auto sig = s.sign(CKM_SHA256_RSA_PKCS, hPriv, msg);
    ASSERT_TRUE(!sig.empty());
    s.verify(CKM_SHA256_RSA_PKCS, hPub, msg, sig);
}

void test_rsa_verify_bad_sig() {
    auto s = makeLoggedInSession();
    auto [hPub, hPriv] = s.generateRsaKeyPair(2048);
    std::vector<uint8_t> msg = {1,2,3};
    auto sig = s.sign(CKM_SHA256_RSA_PKCS, hPriv, msg);
    sig[0] ^= 0xFF;
    ASSERT_THROW(s.verify(CKM_SHA256_RSA_PKCS, hPub, msg, sig), CKR_SIGNATURE_INVALID);
}

void test_rsa_pss_sign_verify() {
    auto s = makeLoggedInSession();
    auto [hPub, hPriv] = s.generateRsaKeyPair(2048);
    std::vector<uint8_t> msg = {1,2,3,4,5,6,7,8};
    auto sig = s.sign(CKM_SHA256_RSA_PKCS_PSS, hPriv, msg);
    ASSERT_TRUE(!sig.empty());
    s.verify(CKM_SHA256_RSA_PKCS_PSS, hPub, msg, sig);
}

void test_rsa_oaep_round_trip() {
    auto s = makeLoggedInSession();
    auto [hPub, hPriv] = s.generateRsaKeyPair(2048);
    std::vector<uint8_t> plain = {'s','e','c','r','e','t'};
    auto ct = s.encryptRsaOaep(hPub, plain);
    auto pt = s.decryptRsaOaep(hPriv, ct);
    ASSERT_EQ(pt, plain);
}

// ---------------------------------------------------------------------------
// Tests: EC
// ---------------------------------------------------------------------------

void test_ec_keygen() {
    auto s = makeLoggedInSession();
    auto [hPub, hPriv] = s.generateEcKeyPair();
    ASSERT_TRUE(hPub  != 0);
    ASSERT_TRUE(hPriv != 0);
}

void test_ec_sign_verify() {
    auto s = makeLoggedInSession();
    auto [hPub, hPriv] = s.generateEcKeyPair();
    std::vector<uint8_t> msg(20, 0xCC);
    auto sig = s.sign(CKM_ECDSA, hPriv, msg);
    s.verify(CKM_ECDSA, hPub, msg, sig);
}

// ---------------------------------------------------------------------------
// Tests: AES-GCM
// ---------------------------------------------------------------------------

void test_aes_keygen() {
    auto s = makeLoggedInSession();
    auto hKey = s.generateAesKey(32);
    ASSERT_TRUE(hKey != 0);
}

void test_aes_gcm_round_trip() {
    auto s = makeLoggedInSession();
    auto hKey = s.generateAesKey(32);
    std::vector<uint8_t> iv(12, 0x42);
    std::vector<uint8_t> plain = {'t','e','s','t',' ','d','a','t','a'};
    auto ct = s.encryptAesGcm(hKey, iv, plain);
    auto pt = s.decryptAesGcm(hKey, iv, ct);
    ASSERT_EQ(pt, plain);
}

void test_aes_gcm_tamper() {
    auto s = makeLoggedInSession();
    auto hKey = s.generateAesKey(32);
    std::vector<uint8_t> iv(12, 0x00);
    std::vector<uint8_t> plain = {1,2,3,4,5,6,7,8};
    auto ct = s.encryptAesGcm(hKey, iv, plain);
    ct.back() ^= 0x01;
    ASSERT_THROW(s.decryptAesGcm(hKey, iv, ct), CKR_ENCRYPTED_DATA_INVALID);
}

// ---------------------------------------------------------------------------
// Tests: AES-CBC
// ---------------------------------------------------------------------------

void test_aes_cbc_round_trip() {
    auto s = makeLoggedInSession();
    auto hKey = s.generateAesKey(32);
    std::vector<uint8_t> iv(16, 0x01);
    std::vector<uint8_t> plain = {'H','e','l','l','o',' ','C','B','C'};
    auto ct = s.encryptAesCbc(hKey, iv, plain);
    auto pt = s.decryptAesCbc(hKey, iv, ct);
    ASSERT_EQ(pt, plain);
}

// ---------------------------------------------------------------------------
// Tests: Digest
// ---------------------------------------------------------------------------

void test_sha256() {
    auto s = makeSession();
    std::vector<uint8_t> data = {'a','b','c'};
    auto hash = s.digest(CKM_SHA256, data);
    ASSERT_EQ(hash.size(), (size_t)32);
    ASSERT_EQ(hash[0], (uint8_t)0xba);
}

// ---------------------------------------------------------------------------
// Tests: Random
// ---------------------------------------------------------------------------

void test_random_nonzero() {
    auto s = makeSession();
    auto rnd = s.generateRandom(64);
    ASSERT_EQ(rnd.size(), (size_t)64);
    bool hasNonZero = false;
    for (auto b : rnd) if (b) { hasNonZero = true; break; }
    ASSERT_TRUE(hasNonZero);
}

// ---------------------------------------------------------------------------
// Tests: FindObjects / DestroyObject
// ---------------------------------------------------------------------------

void test_find_and_destroy() {
    auto s = makeLoggedInSession();
    auto hKey = s.generateAesKey(16);
    auto all = s.findAllObjects();
    ASSERT_TRUE(!all.empty());
    s.destroyObject(hKey);
    ASSERT_THROW(s.destroyObject(hKey), CKR_OBJECT_HANDLE_INVALID);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    std::cout << "==============================\n";
    std::cout << "  PKCS#11 C++ Unit Tests\n";
    std::cout << "==============================\n\n";

    pkcs11::Library lib;
    g_lib = &lib;

    std::vector<TestCase> tests = {
        { "library: double init",          test_library_init          },
        { "library: slot list non-empty",  test_slot_list_non_empty   },
        { "session: open/close",           test_open_close_session    },
        { "session: login/logout",         test_login_logout          },
        { "session: wrong PIN",            test_wrong_pin             },
        { "session: double login",         test_double_login          },
        { "rsa: keygen",                   test_rsa_keygen            },
        { "rsa: sign+verify",              test_rsa_sign_verify       },
        { "rsa: verify bad sig",           test_rsa_verify_bad_sig    },
        { "rsa: PSS sign+verify",          test_rsa_pss_sign_verify   },
        { "rsa: OAEP round trip",          test_rsa_oaep_round_trip   },
        { "ec: keygen",                    test_ec_keygen             },
        { "ec: sign+verify",               test_ec_sign_verify        },
        { "aes: keygen",                   test_aes_keygen            },
        { "aes-gcm: round trip",           test_aes_gcm_round_trip    },
        { "aes-gcm: tamper rejection",     test_aes_gcm_tamper        },
        { "aes-cbc: round trip",           test_aes_cbc_round_trip    },
        { "digest: SHA-256",               test_sha256                },
        { "random: non-zero",              test_random_nonzero        },
        { "objects: find+destroy",         test_find_and_destroy      },
    };

    for (auto& tc : tests) run(tc);

    std::cout << "\n------------------------------\n";
    std::cout << "Results: " << g_passed << " passed, " << g_failed << " failed\n";

    return g_failed == 0 ? 0 : 1;
}
