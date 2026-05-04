/***********************************************************************************************************************************
Binary to String Encode/Decode

Thin C wrappers over the Rust implementation in `crates/pgbr-encode`. The actual encoding logic lives in libpgbr_ffi.a; this file
keeps the public API in src/common/encode.h byte-identical to the legacy version, translating between the C calling convention
and the Rust thread-local last-error machinery.
***********************************************************************************************************************************/
#include <build.h>

#include <stdint.h>

#include "common/debug.h"
#include "common/encode.h"
#include "pgbr_ffi.h"

/**********************************************************************************************************************************/
FN_EXTERN void
encodeToStr(const EncodingType type, const uint8_t *const source, const size_t sourceSize, char *const destination)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ENUM, type);
        FUNCTION_TEST_PARAM_P(BYTEDATA, source);
        FUNCTION_TEST_PARAM(SIZE, sourceSize);
        FUNCTION_TEST_PARAM_P(CHARDATA, destination);
    FUNCTION_TEST_END();

    pgbr_encode_to_str((int32_t)type, source, sourceSize, destination);

    if (pgbr_last_error_code() != 0)
        THROW_FMT(FormatError, "%s", pgbr_last_error_msg());

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN size_t
encodeToStrSize(const EncodingType type, const size_t sourceSize)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ENUM, type);
        FUNCTION_TEST_PARAM(SIZE, sourceSize);
    FUNCTION_TEST_END();

    const size_t result = pgbr_encode_to_str_size((int32_t)type, sourceSize);

    if (pgbr_last_error_code() != 0)
        THROW_FMT(FormatError, "%s", pgbr_last_error_msg());

    FUNCTION_TEST_RETURN(SIZE, result);
}

/**********************************************************************************************************************************/
FN_EXTERN void
decodeToBin(const EncodingType type, const char *const source, uint8_t *const destination)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ENUM, type);
        FUNCTION_TEST_PARAM(STRINGZ, source);
        FUNCTION_TEST_PARAM_P(BYTEDATA, destination);
    FUNCTION_TEST_END();

    if (pgbr_decode_to_bin((int32_t)type, source, destination) != 0)
        THROW_FMT(FormatError, "%s", pgbr_last_error_msg());

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN size_t
decodeToBinSize(const EncodingType type, const char *const source)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ENUM, type);
        FUNCTION_TEST_PARAM(STRINGZ, source);
    FUNCTION_TEST_END();

    size_t result = 0;

    if (pgbr_decode_to_bin_size((int32_t)type, source, &result) != 0)
        THROW_FMT(FormatError, "%s", pgbr_last_error_msg());

    FUNCTION_TEST_RETURN(SIZE, result);
}
