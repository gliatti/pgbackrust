/***********************************************************************************************************************************
Gz Compress

Thin C wrapper over the Rust streaming compressor in `crates/pgbr-compress::gz::compress`. The IoFilter object, debug logging
helpers, and inputSame state machine stay on the C side because they plug into pgBackRust's IoFilter wrapper (not migrated yet);
the libz `deflateInit2_` / `deflate` / `deflateEnd` calls are replaced by FFI calls into libpgbr_ffi.a, which keeps the legacy
parameters (`memLevel = 9`, `Z_DEFAULT_STRATEGY`, `windowBits = 15` for raw / `31` for gzip) so the compressed output is
byte-identical to the legacy path.

The legacy code held a `z_stream` directly in the GzCompress struct; this shim replaces it with an opaque `void *state`
pointer to the Rust `Compress`. A single deflate-tick FFI call (`pgbr_gz_compress_state_deflate`) drives the encoder, returns
the number of bytes consumed / written and the raw zlib status, and the C side translates errors via `gzError`.
***********************************************************************************************************************************/
#include <build.h>

#include <stdio.h>

#include "common/compress/common.h"
#include "common/compress/gz/common.h"
#include "common/compress/gz/compress.h"
#include "common/debug.h"
#include "common/io/filter/filter.h"
#include "common/log.h"
#include "common/macro.h"
#include "common/type/object.h"
#include "common/type/pack.h"
#include "pgbr_ffi.h"

// Mirror of the zlib `Z_STREAM_END` constant (`zlib.h`). Replicated here so this module no longer needs to include `<zlib.h>` —
// the only remaining touchpoint is interpreting the success return code from `pgbr_gz_compress_state_deflate`, which forwards
// libz's raw return code unchanged.
#define GZ_COMPRESS_STREAM_END                                      1

/***********************************************************************************************************************************
Object type
***********************************************************************************************************************************/
typedef struct GzCompress
{
    void *state;                                                    // Opaque pgbr_compress::gz::compress::Compress*
    size_t inputAvail;                                              // Bytes still unconsumed from the current input buffer
    const unsigned char *inputPtr;                                  // Pointer to the start of the unconsumed slice (into caller's
                                                                    // Buffer; the IoFilter framework keeps it alive while
                                                                    // inputSame is true)

    bool inputSame;                                                 // Is the same input required on the next process call?
    bool flushing;                                                  // Is input complete and flushing in progress?
    bool done;                                                      // Is compression done?
} GzCompress;

/***********************************************************************************************************************************
Macros for function logging
***********************************************************************************************************************************/
static void
gzCompressToLog(const GzCompress *const this, StringStatic *const debugLog)
{
    strStcFmt(
        debugLog, "{inputSame: %s, done: %s, flushing: %s, availIn: %zu}", cvtBoolToConstZ(this->inputSame),
        cvtBoolToConstZ(this->done), cvtBoolToConstZ(this->flushing), this->inputAvail);
}

#define FUNCTION_LOG_GZ_COMPRESS_TYPE                                                                                              \
    GzCompress *
#define FUNCTION_LOG_GZ_COMPRESS_FORMAT(value, buffer, bufferSize)                                                                 \
    FUNCTION_LOG_OBJECT_FORMAT(value, gzCompressToLog, buffer, bufferSize)

/***********************************************************************************************************************************
Free deflate stream
***********************************************************************************************************************************/
static void
gzCompressFreeResource(THIS_VOID)
{
    THIS(GzCompress);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(GZ_COMPRESS, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    pgbr_gz_compress_state_free(this->state);
    this->state = NULL;

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Compress data
***********************************************************************************************************************************/
static void
gzCompressProcess(THIS_VOID, const Buffer *const uncompressed, Buffer *const compressed)
{
    THIS(GzCompress);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(GZ_COMPRESS, this);
        FUNCTION_LOG_PARAM(BUFFER, uncompressed);
        FUNCTION_LOG_PARAM(BUFFER, compressed);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(!this->done);
    ASSERT(compressed != NULL);
    ASSERT(!this->flushing || uncompressed == NULL);
    ASSERT(this->flushing || (!this->inputSame || this->inputAvail != 0));

    // Flushing
    if (uncompressed == NULL)
    {
        this->inputAvail = 0;
        this->inputPtr = NULL;
        this->flushing = true;
    }
    // More input
    else if (!this->inputSame)
    {
        this->inputAvail = bufUsed(uncompressed);
        this->inputPtr = bufPtrConst(uncompressed);
    }

    // Run one deflate tick. The Rust state owns the libz `z_stream`; this call translates
    // to a single `deflate(stream, this->flushing ? Z_FINISH : Z_NO_FLUSH)` invocation.
    size_t written = 0;
    size_t consumed = 0;
    const int result = pgbr_gz_compress_state_deflate(
        this->state, this->inputPtr, this->inputAvail, bufRemainsPtr(compressed), bufRemains(compressed), this->flushing,
        &written, &consumed);

    // Surface zlib errors via the legacy classifier so we get the same `[code] message`
    // exception text the C path used to throw (and AssertError for the FFI-side `-100`
    // sentinel, which falls into the "unknown error" bucket).
    gzError(result);

    // Set buffer used space
    bufUsedInc(compressed, written);

    // Advance the unconsumed-input cursor
    this->inputAvail -= consumed;
    this->inputPtr += consumed;

    // Is compression done?
    if (this->flushing && result == GZ_COMPRESS_STREAM_END)
        this->done = true;

    // Can more input be provided on the next call?
    this->inputSame = this->flushing ? !this->done : this->inputAvail != 0;

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Is compress done?
***********************************************************************************************************************************/
static bool
gzCompressDone(const THIS_VOID)
{
    THIS(const GzCompress);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(GZ_COMPRESS, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->done);
}

/***********************************************************************************************************************************
Is the same input required on the next process call?
***********************************************************************************************************************************/
static bool
gzCompressInputSame(const THIS_VOID)
{
    THIS(const GzCompress);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(GZ_COMPRESS, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->inputSame);
}

/**********************************************************************************************************************************/
FN_EXTERN IoFilter *
gzCompressNew(const int level, const bool raw)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(INT, level);
        FUNCTION_LOG_PARAM(BOOL, raw);
    FUNCTION_LOG_END();

    ASSERT(level >= GZ_COMPRESS_LEVEL_MIN && level <= GZ_COMPRESS_LEVEL_MAX);

    OBJ_NEW_BEGIN(GzCompress, .childQty = MEM_CONTEXT_QTY_MAX, .callbackQty = 1)
    {
        *this = (GzCompress){.state = NULL};

        // Create the Rust streaming compressor. The FFI returns the raw zlib code via
        // `errCode` on failure; route it through `gzError` so we get the same exception
        // type / message text the legacy `gzError(deflateInit2(...))` would have raised.
        int32_t errCode = 0;
        this->state = pgbr_gz_compress_state_new(level, raw, &errCode);

        if (this->state == NULL)
        {
            pgbr_last_error_clear();
            gzError(errCode);
        }

        // Set free callback to ensure deflateEnd is called on context destruction
        memContextCallbackSet(objMemContext(this), gzCompressFreeResource, this);
    }
    OBJ_NEW_END();

    FUNCTION_LOG_RETURN(
        IO_FILTER,
        ioFilterNewP(
            GZ_COMPRESS_FILTER_TYPE, this, compressParamList(level, raw), .done = gzCompressDone, .inOut = gzCompressProcess,
            .inputSame = gzCompressInputSame));
}
