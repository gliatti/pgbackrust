/***********************************************************************************************************************************
Blob Handler

Thin C shims over `pgbr-core::blob`. The `struct Blob { char *block; size_t pos; }` layout is mirrored byte-for-byte by the Rust
side via `#[repr(C)]`; the public header keeps the opaque `typedef struct Blob Blob;`.
***********************************************************************************************************************************/
#include <build.h>

#include "common/debug.h"
#include "common/error/error.h"
#include "common/memContext.h"
#include "common/type/blob.h"
#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Object type — kept here so `sizeof(Blob)` resolves for any shim caller that links against the C ABI through the legacy header.
The Rust side owns the canonical layout via `#[repr(C)]` and the two pointer-sized fields in the same order.
***********************************************************************************************************************************/
struct Blob
{
    char *block;                                                    // Current block for writing
    size_t pos;                                                     // Position in current block
};

/**********************************************************************************************************************************/
FN_EXTERN Blob *
blbNew(void)
{
    FUNCTION_TEST_VOID();

    FUNCTION_TEST_RETURN(BLOB, pgbr_blob_new(errorTryDepth()));
}

/**********************************************************************************************************************************/
FN_EXTERN const void *
blbAdd(Blob *const this, const void *const data, const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(BLOB, this);
        FUNCTION_TEST_PARAM_P(VOID, data);
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    const void *const result = pgbr_blob_add(this, data, size, errorTryDepth());

    FUNCTION_TEST_RETURN_CONST_P(VOID, result);
}
