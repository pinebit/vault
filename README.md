# VAULT

> Vault is a tiny C++ library that manages password-protected files.

The library is using OpenSSL for data encryption, specifically:
- `PKCS5_PBKDF2_HMAC_SHA1` for key derivation,
- `EVP_aes_256_cbc` cipher for encryption,
- `HMAC` with `EVP_sha256` for digest.

The internal file structure is composed with protobuf.

## Build Dependencies

- protobuf (v3.x)
- openssl (v1.1.x)
- gtest/gmock

## API

API consists of the three easy calls: `create()`, `read()` and `update()`:

```cpp
    // marker interfaces
    typedef std::vector<uint8_t> token_t;
    typedef std::vector<uint8_t> userdata_t;

    // Creates a new password protected file from userdata.
    // Returns token that can be used to authorize read() or update() without providing a password.
    // Note: an existing file will be overwritten and truncated.
    token_t create(const std::string &path, const std::string &password, const userdata_t &userdata);

    // Reads and decrypts the encrypted file protected with the password.
    // If a wrong password is specified, this throws runtime_error exception.
    userdata_t read(const std::string &path, const std::string &password, token_t *token = nullptr);

    // Reads and decrypts the encrypted file using the token instead of a password.
    userdata_t read(const std::string &path, const token_t &token);

    // Updates the encrypted file contents using the token instead of a password.
    void update(const std::string &path, const token_t &token, const userdata_t &userdata);
```

A special parameter of type `token_t` is simply a vector that holds cipher encryption parameters (but not password).
Using the token instead of password can improve the security because you don't need to store user entered password between API calls.
However, when you are done manipulating the files, you need to wipe the token for better security.

## Sample Usage

```cpp
  // 1. create an encrypted file
  vault::create("vault.bin", "Qwerty123!", mySensitiveData);
  
  // 2. read the encrypted file later (assuming user has entered its password)
  auto mySensitiveData = vault::read("vault.bin", "Qwerty123!");
```

Alternatively, if you need accessing the encrypted files many times during the application's
lifetime and you don't want retaining the user's password in memory, consider using the token as following:
```
   // 1. create an encrypted file, receive the token and keep it in memory
   auto token = vault::create("vault.bin", "Qwerty123!", mySensitiveData);
   
   // 2. update file if needed at any time
   vault::create("vault.bin", token, myUpdatedSensitiveData);
   
   // 3. now read the sensitive content using token (no password prompt)
   auto myData = vault::read("vault.bin", token);
```

## License

MIT

## AD

If you are interested in building a custom security solution, ask me how: pinebit@gmail.com

If you need even more rock-star devs: https://www.toptal.com/#obtain-just-solid-hackers

