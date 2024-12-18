#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/evp.h>

char *md5(const char *str, int length) {
    EVP_MD_CTX *mdctx;
    unsigned int md5_digest_len = EVP_MD_size(EVP_md5());
    uint8_t md5_digest[md5_digest_len];
    char *hexdigest = malloc(md5_digest_len * 2 + 1);

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);

    // Process the input in correct-sized chunks
    while (length > 0) {
        int chunk = (length > 512) ? 512 : length;
        EVP_DigestUpdate(mdctx, str, chunk);
        length -= chunk;
        str += chunk;
    }

    EVP_DigestFinal_ex(mdctx, md5_digest, &md5_digest_len);
    EVP_MD_CTX_free(mdctx);

    for (int n = 0; n < md5_digest_len; ++n) {
        snprintf(hexdigest + n*2, 3, "%02x", md5_digest[n]);
    }
    hexdigest[md5_digest_len * 2] = '\0';

    return hexdigest;
}
