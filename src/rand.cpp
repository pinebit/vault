#include <cassert>
#include <openssl/rand.h>
#include "rand.h"


vault::blob_t vault::rand(int size)
{
    assert(size > 0);

    blob_t buffer(size, '\0');

    int rv = RAND_bytes(buffer.data(), size);
    assert(rv == 1);

    return buffer;
}
