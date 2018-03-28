#include <openssl/evp.h>
#include <algorithm>
#include <iostream>
#include <cassert>
#include "aes.h"

using namespace vault;

static blob_t run_evp_cipher(const blob_t &input, const blob_t &key, const blob_t &iv, int enc)
{
    auto ctx = EVP_CIPHER_CTX_new();
    assert(ctx);

    if (1 != EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), nullptr, nullptr, nullptr, enc) ||
        EVP_CIPHER_CTX_key_length(ctx) != key.size() ||
        EVP_CIPHER_CTX_iv_length(ctx) != iv.size()) {
        throw std::runtime_error("wrong AES cipher parameters");
    }

    blob_t output;
    blob_t buffer(input.size() + EVP_MAX_BLOCK_LENGTH, '\0');

    if (1 == EVP_CipherInit_ex(ctx, nullptr, nullptr, key.data(), iv.data(), enc)) {
        int len = 0;
        if (1 == EVP_CipherUpdate(ctx, buffer.data(), &len, input.data(), (int)input.size())) {
            int buffer_size = len;
            if (1 == EVP_CipherFinal_ex(ctx, buffer.data() + len, &len)) {
                buffer_size += len;
                output.resize((size_t)buffer_size);
                std::copy(buffer.begin(), buffer.begin() + buffer_size, output.begin());
            }
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    return output;
}

blob_t vault::encrypt(const blob_t &data, const blob_t &key, const blob_t &iv)
{
    return run_evp_cipher(data, key, iv, 1);
}

blob_t vault::decrypt(const blob_t &data, const blob_t &key, const blob_t &iv)
{
    return run_evp_cipher(data, key, iv, 0);
}
