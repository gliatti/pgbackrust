/***********************************************************************************************************************************
Gz Decompress

Thin C wrapper over the Rust streaming decompressor in `crates/pgbr-compress::gz::decompress`. The IoFilter object, debug
logging helpers, and `inputSame` state machine stay on the C side; the libz `inflateInit2_` / `inflate` / `inflateEnd` calls
are replaced by FFI calls into libpgbr_ffi.a (same `windowBits = 15` raw / `31` gzip parameters as the legacy code).

The legacy code held a `z_stream` directly in the GzDecompress struct. This shim replaces it with an opaque `void *state`
pointer to the Rust `Decompress`, plus an `(inputPtr, inputAvail)` cursor that tracks how many bytes of the current input
buffer remain unconsumed. The struct still exposes `inputSame` and `done` as public fields because the test suite asserts
log output against them (see `compressTest.c::"gz"` `gzDecompressToLog` block).
***********************************************************************************************************************************/
#include <build.h>

#include <stdio.h>

#include "common/compress/common.h"
#include "common/compress/gz/common.h"
#include "common/compress/gz/decompress.h"
#include "common/debug.h"
#include "common/io/filter/filter.h"
#include "common/log.h"
#include "common/macro.h"
#include "common/type/object.h"
#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Object type
***********************************************************************************************************************************/
typedef struct GzDecompress
{
    void *state;                                                    // Opaque pgbr_compress::gz::decompress::Decompress*
    size_t inputAvail;                                              // Bytes still unconsumed from the current input buffer
    const unsigned char *inputPtr;                                  // Pointer to the unconsumed slice; valid while inputSame=true

    bool inputSame;                                                 // Is the same input required on the next process call?
    bool done;                                                      // Is decompression done?
} GzDecompress;

/***********************************************************************************************************************************
Macros for function logging
***********************************************************************************************************************************/
static void
gzDecompressToLog(const GzDecompress *const this, StringStatic *const debugLog)
{
    strStcFmt(
        debugLog, "{inputSame: %s, done: %s, availIn: %zu}", cvtBoolToConstZ(this->inputSame), cvtBoolToConstZ(this->done),
        this->inputAvail);
}

#define FUNCTION_LOG_GZ_DECOMPRESS_TYPE                                                                                            \
    GzDecompress *
#define FUNCTION_LOG_GZ_DECOMPRESS_FORMAT(value, buffer, bufferSize)                                                               \
    FUNCTION_LOG_OBJECT_FORMAT(value, gzDecompressToLog, buffer, bufferSize)

/***********************************************************************************************************************************
Free inflate stream
***********************************************************************************************************************************/
static void
gzDecompressFreeResource(THIS_VOID)
{
    THIS(GzDecompress);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(GZ_DECOMPRESS, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    pgbr_gz_decompress_state_free(this->state);
    this->state = NULL;

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Decompress data
***********************************************************************************************************************************/
static void
gzDecompressProcess(THIS_VOID, const Buffer *const compressed, Buffer *const uncompressed)
{
    THIS(GzDecompress);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(GZ_DECOMPRESS, this);
        FUNCTION_LOG_PARAM(BUFFER, compressed);
        FUNCTION_LOG_PARAM(BUFFER, uncompressed);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(uncompressed != NULL);

    // There should never be a flush because in a valid compressed stream the end of data can be determined and done will be set.
    // If a flush is received it means the compressed stream terminated early, e.g. a zero-length or truncated file.
    if (compressed == NULL)
        THROW(FormatError, "unexpected eof in compressed data");

    if (!this->inputSame)
    {
        this->inputAvail = bufUsed(compressed);
        this->inputPtr = bufPtrConst(compressed);
    }

    // Run one inflate tick. The Rust state owns the libz `z_stream`; this call translates
    // to a single `inflate(stream, Z_NO_FLUSH)` invocation.
    size_t written = 0;
    size_t consumed = 0;
    const int result = pgbr_gz_decompress_state_inflate(
        this->state, this->inputPtr, this->inputAvail, bufRemainsPtr(uncompressed), bufRemains(uncompressed), &written,
        &consumed);

    // Surface zlib errors via the legacy classifier so we get the same `[code] message`
    // exception text the C path used to throw.
    gzError(result);

    // Set buffer used space
    bufUsedInc(uncompressed, written);

    // Advance the unconsumed-input cursor
    this->inputAvail -= consumed;
    this->inputPtr += consumed;

    // Is decompression done? `result == 1` is the FFI's mirror of `Z_STREAM_END`.
    this->done = result == 1;

    // Is the same input expected on the next call?
    this->inputSame = this->done ? false : this->inputAvail != 0;

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Is decompress done?
***********************************************************************************************************************************/
static bool
gzDecompressDone(const THIS_VOID)
{
    THIS(const GzDecompress);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(GZ_DECOMPRESS, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->done);
}

/***********************************************************************************************************************************
Is the same input required on the next process call?
***********************************************************************************************************************************/
static bool
gzDecompressInputSame(const THIS_VOID)
{
    THIS(const GzDecompress);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(GZ_DECOMPRESS, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->inputSame);
}

/**********************************************************************************************************************************/
FN_EXTERN IoFilter *
gzDecompressNew(const bool raw)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(BOOL, raw);
    FUNCTION_LOG_END();

    OBJ_NEW_BEGIN(GzDecompress, .childQty = MEM_CONTEXT_QTY_MAX, .callbackQty = 1)
    {
        *this = (GzDecompress){.state = NULL};

        // Create the Rust streaming decompressor. The FFI returns the raw zlib code via
        // `errCode` on failure; route it through `gzError` so we get the same exception
        // type / message text the legacy `gzError(inflateInit2(...))` would have raised.
        int32_t errCode = 0;
        this->state = pgbr_gz_decompress_state_new(raw, &errCode);

        if (this->state == NULL)
        {
            pgbr_last_error_clear();
            gzError(errCode);
        }

        // Set free callback to ensure inflateEnd is called on context destruction
        memContextCallbackSet(objMemContext(this), gzDecompressFreeResource, this);
    }
    OBJ_NEW_END();

    FUNCTION_LOG_RETURN(
        IO_FILTER,
        ioFilterNewP(
            GZ_DECOMPRESS_FILTER_TYPE, this, decompressParamList(raw), .done = gzDecompressDone, .inOut = gzDecompressProcess,
            .inputSame = gzDecompressInputSame));
}
