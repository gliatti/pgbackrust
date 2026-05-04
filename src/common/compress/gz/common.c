/***********************************************************************************************************************************
Gz Common

Thin C wrappers over the Rust implementation in `crates/pgbr-compress::gz`. The zlib error-code → pgBackRust exception-type
mapping lives in libpgbr_ffi.a; this file keeps the public API in `src/common/compress/gz/common.h` byte-identical to the
legacy version, plugging the classification result back into pgBackRust's `THROWP_FMT` machinery.
***********************************************************************************************************************************/
#include <build.h>

#include "common/compress/gz/common.h"
#include "common/debug.h"
#include "pgbr_ffi.h"

/**********************************************************************************************************************************/
FN_EXTERN int
gzError(const int error)
{
    int32_t kindCode = 0;
    char message[64];

    if (pgbr_gz_error_classify(error, &kindCode, message, sizeof(message)) == 1)
    {
        const ErrorType *errorType;

        switch (kindCode)
        {
            case 1:
                errorType = &FormatError;
                break;

            case 2:
                errorType = &MemoryError;
                break;

            default:
                errorType = &AssertError;
                break;
        }

        THROWP_FMT(errorType, "zlib threw error: [%d] %s", error, message);
    }

    return error;
}
