/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

/// @file pkcs11_test_env_setup.hpp
/// @brief Encapsulated filesystem and environment setup for PKCS#11 software simulators.
///
/// Prepares isolated storage directories and configuration files for active
/// software backends (SoftHSM2 and Rust Cryptoki), keeping test fixtures strictly
/// focused on generic OASIS PKCS#11 C API behaviors.

#ifndef SCORE_CRYPTO_TESTS_PKCS11_PKCS11_TEST_ENV_SETUP_HPP
#define SCORE_CRYPTO_TESTS_PKCS11_PKCS11_TEST_ENV_SETUP_HPP

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <unistd.h>

#include <gtest/gtest.h>

#include "score/tests/utility/test_utility.hpp"

namespace tests::pkcs11::env
{

/// @brief Generates a thread-safe, collision-free temporary directory under TEST_TMPDIR
/// using S-CORE's standard tests::utility::TempDirectory utility.
///
/// Incorporates ::getpid() so that even if TEST_TMPDIR is unset (fallback to /tmp),
/// concurrent test processes will never collide.
///
/// @param prefix Distinguishing prefix for the test suite (e.g. "pkcs11_fixture").
/// @return Full filesystem path as a std::string.
inline std::string UniqueTestDirectory(std::string_view prefix)
{
    static std::atomic<unsigned int> s_test_counter{0U};
    const std::string dir_name = std::string(prefix) + "_" + std::to_string(::getpid()) + "_" +
                                 std::to_string(++s_test_counter);
    return ::tests::utility::TempDirectory(dir_name).string();
}

/// @brief Prepares backend-specific filesystem storage and environment variables
/// for active software PKCS#11 simulators (SoftHSM2 and Rust Cryptoki).
///
/// @param test_dir Isolated directory in TEST_TMPDIR unique to the running test case.
/// @param num_slots Number of slots to configure for multi-slot tests (default: 1).
/// @return True on success, false if any filesystem or configuration operation failed.
[[nodiscard]] inline bool PrepareBackendEnvironments(const std::string& test_dir, unsigned int num_slots = 1U)
{
    std::error_code ec;
    std::filesystem::remove_all(test_dir, ec);
    if (ec)
    {
        return false;
    }

    // 1. SoftHSM2 configuration
    const std::string softhsm_token_dir = test_dir + "/softhsm_tokens";
    const std::string softhsm_conf_path = test_dir + "/softhsm2.conf";
    std::filesystem::create_directories(softhsm_token_dir, ec);
    if (ec)
    {
        return false;
    }

    {
        std::ofstream cfg(softhsm_conf_path, std::ios::trunc);
        if (!cfg.is_open())
        {
            return false;
        }
        cfg << "directories.tokendir = " << softhsm_token_dir << "\n";
        cfg << "objectstore.backend = file\n";
        cfg << "log.level = INFO\n";
        if (!cfg.good())
        {
            return false;
        }
    }
    // NOLINTNEXTLINE(concurrency-mt-unsafe) -- test fixture setup, single-threaded
    ::setenv("SOFTHSM2_CONF", softhsm_conf_path.c_str(), 1);

    // 2. Rust Cryptoki storage
    const std::string cryptoki_token_dir = test_dir + "/cryptoki_tokens";
    const std::string cryptoki_store_path = cryptoki_token_dir + "/token.json";
    std::filesystem::create_directories(cryptoki_token_dir, ec);
    if (ec)
    {
        return false;
    }
    // NOLINTNEXTLINE(concurrency-mt-unsafe) -- test fixture setup, single-threaded
    ::setenv("CRYPTOKI_STORE", cryptoki_store_path.c_str(), 1);

    // 3. Multi-slot configuration
    if (num_slots > 1U)
    {
        // NOLINTNEXTLINE(concurrency-mt-unsafe) -- test fixture setup, single-threaded
        ::setenv("CRYPTOKI_NUM_SLOTS", std::to_string(num_slots).c_str(), 1);
    }
    return true;
}

/// @brief Cleanly unsets software backend environment variables on teardown.
inline void CleanupBackendEnvironments()
{
    // NOLINTNEXTLINE(concurrency-mt-unsafe) -- test fixture teardown, single-threaded
    ::unsetenv("SOFTHSM2_CONF");
    // NOLINTNEXTLINE(concurrency-mt-unsafe) -- test fixture teardown, single-threaded
    ::unsetenv("CRYPTOKI_STORE");
    // NOLINTNEXTLINE(concurrency-mt-unsafe) -- test fixture teardown, single-threaded
    ::unsetenv("CRYPTOKI_NUM_SLOTS");
}

}  // namespace tests::pkcs11::env

#endif  // SCORE_CRYPTO_TESTS_PKCS11_PKCS11_TEST_ENV_SETUP_HPP
