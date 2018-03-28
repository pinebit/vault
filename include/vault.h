#ifndef VAULT_H
#define VAULT_H

#include <string>
#include <vector>
#include <ostream>

namespace vault {

    // marker interfaces
    typedef std::vector<uint8_t> token_t;
    typedef std::vector<uint8_t> userdata_t;

    // Creates a new password protected file from userdata.
    // Returns token that can be used to authorize read() or update() without providing a password.
    // Note: an existing file will be overwritten and truncated.
    token_t create(const std::string &path, const std::string &password, const userdata_t &userdata);

    // Reads and decrypts the encrypted file protected with the password.
    // If a wrong password specified, this throws logic_error exception.
    userdata_t read(const std::string &path, const std::string &password, token_t *token = nullptr);

    // Reads and decrypts the encrypted file using the token instead of password.
    userdata_t read(const std::string &path, const token_t &token);

    // Updates the encrypted file contents using the token instead of password.
    void update(const std::string &path, const token_t &token, const userdata_t &userdata);

}

#endif // VAULT_H
