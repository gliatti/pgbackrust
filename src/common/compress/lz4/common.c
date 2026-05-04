/***********************************************************************************************************************************
LZ4 Common

Thin C wrapper over the Rust implementation in `crates/pgbr-compress::lz4::error`. The error-classification logic
(`LZ4F_isError` + `LZ4F_getErrorName`) lives in libpgbr_ffi.a now; this file keeps the public API in
`src/common/compress/lz4/common.h` byte-identical to the legacy version, plugging the classification result back into
pgBackRust's `THROWP_FMT` machinery.
***********************************************************************************************************************************/
#include <build.h>

#include <stddef.h>                                                     // For size_t / ssize_t — the public lz4/common.h header
                                                                        // uses both, and the legacy `#include <lz4frame.h>` no
                                                                        // longer sits at the top of this file to pull them in.
#include <sys/types.h>

#include "common/compress/lz4/common.h"
#include "common/debug.h"
#include "pgbr_ffi.h"

/**********************************************************************************************************************************/
FN_EXTERN size_t
lz4Error(const size_t error)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(SIZE, error);
    FUNCTION_TEST_END();

    char message[64];

    if (pgbr_lz4_error_classify(error, message, sizeof(message)) == 1)
        THROW_FMT(FormatError, "lz4 error: [%zd] %s", (ssize_t)error, message);

    FUNCTION_TEST_RETURN_TYPE(size_t, error);
}
