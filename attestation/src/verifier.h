#ifndef VERIFIER_H
#define VERIFIER_H

#include <stdint.h>

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <wolfssl/wolfcrypt/types.h>

#include "app_types.h"

int verifier_verify_quote(const WOLFTPM2_KEY *ak,
                          const Quote_In *quote_in,
                          const Quote_Out *quote_out,
                          byte pcr_values[PCR_COUNT][PCR_MAX_DIGEST_SIZE],
                          TPMI_ALG_HASH pcr_bank_alg,
                          int pcr_digest_size);

uint32_t verifier_signature_size(const TPMT_SIGNATURE *signature);

#endif
