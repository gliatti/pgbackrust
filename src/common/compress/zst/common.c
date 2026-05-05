/***********************************************************************************************************************************
ZST Common

Thin C wrapper over the Rust implementation in `crates/pgbr-compress::zst::error`. The libzstd error-code → pgBackRust
exception-type mapping lives in libpgbr_ffi.a; this file keeps the public API in `src/common/compress/zst/common.h`
byte-identical to the legacy version, plugging the classification result back into pgBackRust's `THROW_FMT` machinery.
***********************************************************************************************************************************/
#include <build.h>

#ifdef HAVE_LIBZST

#include <stddef.h>
#include <sys/types.h>

#include "common/compress/zst/common.h"
#include "common/debug.h"
#include "pgbr_ffi.h"

/**********************************************************************************************************************************/
FN_EXTERN size_t
zstError(const size_t error)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(SIZE, error);
    FUNCTION_TEST_END();

    char message[64];

    if (pgbr_zst_error_classify(error, message, sizeof(message)) == 1)
        THROW_FMT(FormatError, "zst error: [%zd] %s", (ssize_t)error, message);

    FUNCTION_TEST_RETURN(SIZE, error);
}

#endif // HAVE_LIBZST
