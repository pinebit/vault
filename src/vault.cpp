#include <vault.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include "vault.pb.h"
#include "rand.h"
#include "secret.h"
#include "aes.h"
#include "token.h"

const int AES_KEY_SIZE = 32;
const int IV_SIZE = 16;
const int SALT_SIZE = 16;
const int HMAC_KEY_SIZE = 32;

using namespace std;
using namespace vault;

static blob_t make_blob(const string &str) {
    return blob_t(str.begin(), str.end());
}

static string tohex(const blob_t &blob) {
    std::string hex_tmp;
    for (auto x : blob) {
        ostringstream oss;
        oss << hex << setw(2) << setfill('0') << (unsigned)x;
        hex_tmp += oss.str();
    }
    return hex_tmp;
}

token_t vault::create(const string &path, const string &password, const userdata_t &userdata)
{
    blob_t salt = rand(SALT_SIZE);
    const int secret_size = AES_KEY_SIZE + IV_SIZE + HMAC_KEY_SIZE;
    int iterations = estimate_iterations(password, salt, secret_size);
    blob_t secret = generate_secret(password, salt, iterations, secret_size);
    blob_t hmac = calc_hmac(secret, HMAC_KEY_SIZE);

    blob_t aes_key(secret.cbegin(), secret.cbegin() + AES_KEY_SIZE);
    blob_t aes_iv(secret.cbegin() + AES_KEY_SIZE, secret.cbegin() + AES_KEY_SIZE + IV_SIZE);
    blob_t encrypted = encrypt(userdata, aes_key, aes_iv);

    auto authentication = new Authentication;
    authentication->set_iterations(iterations);
    authentication->set_salt(salt.data(), salt.size());
    authentication->set_hmac(hmac.data(), hmac.size());

    Store store;
    store.set_allocated_authentication(authentication);
    store.set_contents(encrypted.data(), encrypted.size());

    fstream file(path, ios::out | ios::binary | ios::trunc);
    if (!store.SerializeToOstream(&file)) {
        throw logic_error("vault data serialization failed");
    }

    return encode_token(*authentication, aes_key, aes_iv);
}

userdata_t vault::read(const string &path, const string &password, token_t *token)
{
    Store store;
    fstream file(path, ios::in | ios::binary);
    store.ParseFromIstream(&file);

    blob_t salt(make_blob(store.authentication().salt()));
    blob_t hmac(make_blob(store.authentication().hmac()));
    const int secret_size = AES_KEY_SIZE + IV_SIZE + HMAC_KEY_SIZE;
    blob_t secret = generate_secret(password, salt, store.authentication().iterations(), secret_size);
    blob_t mac = calc_hmac(secret, HMAC_KEY_SIZE);
    if (mac != hmac) {
        throw logic_error("wrong password");
    }

    blob_t aes_key(secret.begin(), secret.begin() + AES_KEY_SIZE);
    blob_t aes_iv(secret.begin() + AES_KEY_SIZE, secret.begin() + AES_KEY_SIZE + IV_SIZE);

    if (token) {
        *token = encode_token(store.authentication(), aes_key, aes_iv);
    }

    return decrypt(make_blob(store.contents()), aes_key, aes_iv);
}

userdata_t vault::read(const string &path, const token_t &token)
{
    Store store;
    fstream file(path, ios::in | ios::binary);
    if (!store.ParseFromIstream(&file)) {
        throw logic_error("failed to decode vault file");
    }

    Authentication _authentication;
    blob_t aes_key;
    blob_t aes_iv;
    decode_token(token, _authentication, aes_key, aes_iv);

    blob_t contents(make_blob(store.contents()));
    return decrypt(contents, aes_key, aes_iv);
}

void vault::update(const string &path, const token_t &token, const userdata_t &userdata)
{
    Authentication _authentication;
    blob_t aes_key;
    blob_t aes_iv;
    decode_token(token, _authentication, aes_key, aes_iv);
    blob_t encrypted = encrypt(userdata, aes_key, aes_iv);

    Store store;
    fstream ifile(path, ios::in | ios::binary);
    if (!store.ParseFromIstream(&ifile)) {
        throw logic_error("failed to decode vault file");
    }
    store.set_contents(encrypted.data(), encrypted.size());

    fstream ofile(path, ios::out | ios::binary | ios::trunc);
    if (!store.SerializeToOstream(&ofile)) {
        throw logic_error("failed to encode vault file");
    }
}
