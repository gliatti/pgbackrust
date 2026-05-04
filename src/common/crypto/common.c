/***********************************************************************************************************************************
Crypto Common

Thin C wrappers over the Rust implementation in `crates/pgbr-crypto::common`. The actual OpenSSL calls live in libpgbr_ffi.a;
this file keeps the public API in `src/common/crypto/common.h` byte-identical to the legacy version, translating between the C
calling convention and the Rust thread-local last-error machinery.
***********************************************************************************************************************************/
#include <build.h>

#include "common/crypto/common.h"
#include "common/debug.h"
#include "common/log.h"
#include "pgbr_ffi.h"

/**********************************************************************************************************************************/
FN_EXTERN void
cryptoError(const bool error, const char *const description)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(BOOL, error);
        FUNCTION_TEST_PARAM(STRINGZ, description);
    FUNCTION_TEST_END();

    if (error)
        cryptoErrorCode(pgbr_crypto_last_error_get(), description);

    FUNCTION_TEST_RETURN_VOID();
}

FN_EXTERN void
cryptoErrorCode(const unsigned long code, const char *const description)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(UINT64, code);
        FUNCTION_TEST_PARAM(STRINGZ, description);
    FUNCTION_TEST_END();

    char errorMessage[256];
    pgbr_crypto_error_reason_into(code, errorMessage, sizeof(errorMessage));
    THROW_FMT(CryptoError, "%s: [%lu] %s", description, code, errorMessage);

    FUNCTION_TEST_NO_RETURN();
}

/**********************************************************************************************************************************/
FN_EXTERN void
cryptoInit(void)
{
    FUNCTION_LOG_VOID(logLevelTrace);

    pgbr_crypto_init();

    FUNCTION_LOG_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN void
cryptoRandomBytes(uint8_t *const buffer, const size_t size)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM_P(BYTEDATA, buffer);
        FUNCTION_LOG_PARAM(SIZE, size);
    FUNCTION_LOG_END();

    ASSERT(buffer != NULL);
    ASSERT(size > 0);

    pgbr_crypto_random_bytes(buffer, size);

    FUNCTION_LOG_RETURN_VOID();
}
