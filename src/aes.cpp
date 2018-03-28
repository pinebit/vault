#include <openssl/evp.h>
#include <algorithm>
#include <iostream>
#include <cassert>
#include "aes.h"

using namespace vault;

blob_t vault::encrypt(const blob_t &data, const blob_t &key, const blob_t &iv)
{
    auto ctx = EVP_CIPHER_CTX_new();
    assert(ctx);

    if (1 != EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), nullptr, nullptr, nullptr, 1) ||
        EVP_CIPHER_CTX_key_length(ctx) != key.size() ||
        EVP_CIPHER_CTX_iv_length(ctx) != iv.size()) {
        throw std::logic_error("wrong encryption parameters");
    }

    blob_t encrypted;
    blob_t buffer(data.size() + EVP_MAX_BLOCK_LENGTH, '\0');

    if (1 == EVP_CipherInit_ex(ctx, nullptr, nullptr, key.data(), iv.data(), 1)) {
        int len = 0;
        if (1 == EVP_CipherUpdate(ctx, buffer.data(), &len, data.data(), (int)data.size())) {
            int buffer_size = len;
            if (1 == EVP_CipherFinal_ex(ctx, buffer.data() + len, &len)) {
                buffer_size += len;
                encrypted.resize((size_t)buffer_size);
                std::copy(buffer.begin(), buffer.begin() + buffer_size, encrypted.begin());
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return encrypted;
}

blob_t vault::decrypt(const blob_t &data, const blob_t &key, const blob_t &iv)
{
    auto ctx = EVP_CIPHER_CTX_new();
    assert(ctx);

    blob_t decrypted;
    blob_t buffer(data.size(), '\0');
    int outlen = 0, tmplen = 0;

    if (1 == EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data(), 0)) {
        if (1 == EVP_CipherUpdate(ctx, buffer.data(), &outlen, data.data(), (int)data.size())) {
            if (1 == EVP_CipherFinal_ex(ctx, buffer.data() + outlen, &tmplen)) {
                outlen += tmplen;
                decrypted.resize((size_t)outlen);
                std::copy(buffer.begin(), buffer.begin() + outlen, decrypted.begin());
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return decrypted;
}

