#ifndef CRYPTO_PROFILE_H
#define CRYPTO_PROFILE_H

#include "app_types.h"

typedef struct CryptoProfile {
    CryptoMode mode;
    const char *name;
    const char *ek_algorithm;
    const char *srk_algorithm;
    const char *ak_algorithm;
    const char *quote_algorithm;

    int (*create_ek)(WOLFTPM2_DEV *dev, WOLFTPM2_KEY *ek);
    int (*create_srk)(WOLFTPM2_DEV *dev, WOLFTPM2_KEY *srk);
    int (*create_ak)(WOLFTPM2_DEV *dev, WOLFTPM2_KEY *ak, WOLFTPM2_KEY *srk);
    void (*configure_quote)(Quote_In *quote);
} CryptoProfile;

const CryptoProfile *crypto_profile_get(CryptoMode mode);
const byte *crypto_ak_auth(void);
int crypto_ak_auth_size(void);

#endif
