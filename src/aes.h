#ifndef VAULT_AES_H
#define VAULT_AES_H

#include "types.h"

namespace vault {

    blob_t encrypt(const blob_t &data, const blob_t &key, const blob_t &iv);
    blob_t decrypt(const blob_t &data, const blob_t &key, const blob_t &iv);

}

#endif // VAULT_AES_H
