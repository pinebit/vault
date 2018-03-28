#include <openssl/evp.h>
#include <chrono>
#include <cassert>
#include <openssl/hmac.h>
#include "secret.h"

const int MIN_ITERATIONS = 1000;
const int BENCHMARK_ITERATIONS = 10000;
const uint8_t TARGET_TIME_MILLIS = 50;

int vault::estimate_iterations(const std::string &password,
                               const vault::blob_t &salt,
                               int secret_size)
{
    assert(secret_size > 0);
    assert(!password.empty());
    assert(!salt.empty());

    vault::blob_t secretKey(secret_size, '\0');
    auto beginTime = std::chrono::steady_clock::now();

    if (PKCS5_PBKDF2_HMAC_SHA1(
            password.data(), (int)password.size(),
            salt.data(), (int)salt.size(),
            BENCHMARK_ITERATIONS,
            (int)secretKey.size(), secretKey.data()) != 1) {
        return MIN_ITERATIONS;
    }

    auto endTime = std::chrono::steady_clock::now();
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - beginTime);

    const int iterations = (TARGET_TIME_MILLIS * BENCHMARK_ITERATIONS) / (int)milliseconds.count();
    if (iterations < MIN_ITERATIONS) {
        return MIN_ITERATIONS;
    }

    return iterations;
}

vault::blob_t vault::generate_secret(const std::string &password,
                                     const vault::blob_t &salt,
                                     int iterations,
                                     int secret_size)
{
    assert(secret_size > 0);
    assert(!password.empty());
    assert(!salt.empty());

    vault::blob_t secretKey(secret_size, '\0');

    if (PKCS5_PBKDF2_HMAC_SHA1(
            password.data(), (int)password.size(),
            salt.data(), (int)salt.size(),
            iterations,
            (int)secretKey.size(), secretKey.data()) != 1) {
        return vault::blob_t();
    }

    return secretKey;
}

vault::blob_t vault::calc_hmac(const vault::blob_t &secret, int hmac_size)
{
    assert(!secret.empty());
    assert(hmac_size > 0);

    vault::blob_t mac(secret.cend() - hmac_size, secret.cend());
    vault::blob_t result(hmac_size, '\0');
    auto length = (unsigned int)hmac_size;

    HMAC(EVP_sha256(),
         mac.data(), (int)mac.size(),
         secret.data(), (int)secret.size(),
         result.data(), &length);

    return result;
}
