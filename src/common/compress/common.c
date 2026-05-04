/***********************************************************************************************************************************
Compression Common

Thin C wrappers over the Rust implementation in `crates/pgbr-compress::params`. The Pack-encoded byte representation of the
parameter lists is produced in Rust (port of `pckWriteI32P` + `pckWriteBoolP` + `pckWriteEndP` for the legacy `compressParamList`,
and `pckWriteBoolP` + `pckWriteEndP` for `decompressParamList`); the C side just allocates a `Buffer` from the Rust bytes and
casts it to `Pack *` — `Pack` is structurally a `Buffer`, so the cast is the same zero-copy promotion `pckFromBuf` performs.
***********************************************************************************************************************************/
#include <build.h>

#include "common/compress/common.h"
#include "common/debug.h"
#include "common/type/buffer.h"
#include "common/type/object.h"
#include "pgbr_ffi.h"

/**********************************************************************************************************************************/
FN_EXTERN Pack *
compressParamList(const int level, const bool raw)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_LOG_PARAM(INT, level);
        FUNCTION_TEST_PARAM(BOOL, raw);
    FUNCTION_TEST_END();

    Pack *result;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        const size_t size = pgbr_compress_param_list_size((int32_t)level, raw);
        Buffer *const buffer = OBJ_NAME(bufNew(size), Pack::Buffer);
        const size_t written = pgbr_compress_param_list_into((int32_t)level, raw, bufPtr(buffer), size);
        ASSERT(written == size);
        bufUsedSet(buffer, written);

        result = (Pack *)bufMove(buffer, memContextPrior());
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_TEST_RETURN(PACK, result);
}

/**********************************************************************************************************************************/
FN_EXTERN Pack *
decompressParamList(const bool raw)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(BOOL, raw);
    FUNCTION_TEST_END();

    Pack *result;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        const size_t size = pgbr_decompress_param_list_size(raw);
        Buffer *const buffer = OBJ_NAME(bufNew(size), Pack::Buffer);
        const size_t written = pgbr_decompress_param_list_into(raw, bufPtr(buffer), size);
        ASSERT(written == size);
        bufUsedSet(buffer, written);

        result = (Pack *)bufMove(buffer, memContextPrior());
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_TEST_RETURN(PACK, result);
}
