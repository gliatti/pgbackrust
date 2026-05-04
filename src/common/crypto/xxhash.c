/***********************************************************************************************************************************
xxHash Interface

The xxHash maths now live in the Rust `pgbr-crypto` crate, exposed through the FFI shim in libpgbr_ffi.a. This file keeps the
public C API in src/common/crypto/xxhash.h byte-identical and continues to integrate with pgbackrest's IoFilter framework; the
streaming state behind the IoFilter is an opaque pointer owned by Rust.
***********************************************************************************************************************************/
#include <build.h>

#include "common/crypto/xxhash.h"
#include "common/debug.h"
#include "common/io/filter/filter.h"
#include "common/log.h"
#include "common/type/object.h"
#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Object type
***********************************************************************************************************************************/
typedef struct XxHash
{
    size_t size;                                                    // Size of hash to return
    void *state;                                                    // Opaque pointer to a Rust-owned XXH3 state
} XxHash;

/***********************************************************************************************************************************
Macros for function logging
***********************************************************************************************************************************/
#define FUNCTION_LOG_XX_HASH_TYPE                                                                                              \
    XxHash *
#define FUNCTION_LOG_XX_HASH_FORMAT(value, buffer, bufferSize)                                                                 \
    objNameToLog(value, "XxHash", buffer, bufferSize)

/***********************************************************************************************************************************
Free hash context
***********************************************************************************************************************************/
static void
xxHashFreeResource(THIS_VOID)
{
    THIS(XxHash);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(XX_HASH, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    pgbr_xxhash3_state_free(this->state);

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Add message data to the hash from a Buffer
***********************************************************************************************************************************/
static void
xxHashProcess(THIS_VOID, const Buffer *const message)
{
    THIS(XxHash);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(XX_HASH, this);
        FUNCTION_LOG_PARAM(BUFFER, message);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(message != NULL);

    if (pgbr_xxhash3_state_update(this->state, bufPtrConst(message), bufUsed(message)) != 0)
        THROW_FMT(AssertError, "%s", pgbr_last_error_msg());

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Get string representation of the hash as a filter result
***********************************************************************************************************************************/
static Pack *
xxHashResult(THIS_VOID)
{
    THIS(XxHash);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(XX_HASH, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    Pack *result = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        PackWrite *const packWrite = pckWriteNewP();

        uint8_t digest[XX_HASH_SIZE_MAX];
        if (pgbr_xxhash3_state_digest(this->state, digest, this->size) != 0)
            THROW_FMT(AssertError, "%s", pgbr_last_error_msg());

        pckWriteBinP(packWrite, BUF(digest, this->size));
        pckWriteEndP(packWrite);

        result = pckMove(pckWriteResult(packWrite), memContextPrior());
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_LOG_RETURN(PACK, result);
}

/**********************************************************************************************************************************/
FN_EXTERN IoFilter *
xxHashNew(const size_t size)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(SIZE, size);
    FUNCTION_LOG_END();

    ASSERT(size >= 1 && size <= XX_HASH_SIZE_MAX);

    OBJ_NEW_BEGIN(XxHash, .callbackQty = 1)
    {
        *this = (XxHash){.size = size};

        this->state = pgbr_xxhash3_state_new();

        if (this->state == NULL)
            THROW_FMT(AssertError, "%s", pgbr_last_error_msg());

        // Set free callback to ensure hash context is freed
        memContextCallbackSet(objMemContext(this), xxHashFreeResource, this);
    }
    OBJ_NEW_END();

    FUNCTION_LOG_RETURN(IO_FILTER, ioFilterNewP(XX_HASH_FILTER_TYPE, this, NULL, .in = xxHashProcess, .result = xxHashResult));
}

/**********************************************************************************************************************************/
FN_EXTERN Buffer *
xxHashOne(const size_t size, const Buffer *const message)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(SIZE, size);
        FUNCTION_LOG_PARAM(BUFFER, message);
    FUNCTION_LOG_END();

    ASSERT(size >= 1 && size <= XX_HASH_SIZE_MAX);
    ASSERT(message != NULL);

    Buffer *const result = bufNew(size);

    if (pgbr_xxhash3_one(bufPtrConst(message), bufUsed(message), bufPtr(result), size) != 0)
        THROW_FMT(AssertError, "%s", pgbr_last_error_msg());

    bufUsedSet(result, size);

    FUNCTION_LOG_RETURN(BUFFER, result);
}
