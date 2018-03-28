#ifndef VAULT_SECRET_H
#define VAULT_SECRET_H

#include <string>
#include "types.h"

namespace vault {

    int estimate_iterations(const std::string &password,
                            const blob_t &salt,
                            int secret_size);

    blob_t generate_secret(const std::string &password,
                           const blob_t &salt,
                           int iterations,
                           int secret_size);

    blob_t calc_hmac(const blob_t &secret, int hmac_size);
}

#endif // VAULT_SECRET_H
