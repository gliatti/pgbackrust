/***********************************************************************************************************************************
BZ2 Compress

Thin C wrapper over the Rust streaming compressor in `crates/pgbr-compress::bz2::compress`. The IoFilter object, debug logging
helpers, and the inputSame / flushing / done state machine stay on the C side. The libbz2 calls (`BZ2_bzCompressInit`,
`BZ2_bzCompress`, `BZ2_bzCompressEnd`) are replaced by FFI calls into libpgbr_ffi.a.

The legacy code held a `bz_stream` directly in the Bz2Compress struct; this shim replaces it with an opaque `void *state`
plus an `(inputPtr, inputAvail)` cursor. The struct still exposes a small `stream` substruct with a public `avail_in` field
because the test suite asserts log output against it (see `compressTest.c::"bz2"` `bz2CompressToLog` block).
***********************************************************************************************************************************/
#include <build.h>

#include <stdio.h>

#include "common/compress/bz2/common.h"
#include "common/compress/bz2/compress.h"
#include "common/compress/common.h"
#include "common/debug.h"
#include "common/io/filter/filter.h"
#include "common/log.h"
#include "common/macro.h"
#include "common/type/object.h"
#include "common/type/pack.h"
#include "pgbr_ffi.h"

// Mirror of libbz2's `BZ_STREAM_END` constant (`bzlib.h`). Replicated so this module no longer needs `<bzlib.h>` — the only
// touchpoint is interpreting the success return code from `pgbr_bz2_compress_state_compress`.
#define BZ_COMPRESS_STREAM_END                                      4

/***********************************************************************************************************************************
Object type
***********************************************************************************************************************************/
typedef struct Bz2Compress
{
    void *state;                                                    // Opaque pgbr_compress::bz2::compress::Compress*
    size_t inputAvail;                                              // Bytes still unconsumed from the current input buffer
    const unsigned char *inputPtr;                                  // Pointer to the unconsumed slice (into caller's Buffer)

    // The legacy struct exposed `bz_stream stream` directly. The test suite manipulates `stream.avail_in` to validate the log
    // formatter, so keep the field name. Only `avail_in` is read/written externally; everything else has moved into the Rust
    // state pointed to by `this->state`.
    struct {
        unsigned int avail_in;                                      // Mirrored after each FFI tick + writable by tests
    } stream;

    bool inputSame;                                                 // Is the same input required on the next process call?
    bool flushing;                                                  // Is input complete and flushing in progress?
    bool done;                                                      // Is compression done?
} Bz2Compress;

/***********************************************************************************************************************************
Render as string for logging
***********************************************************************************************************************************/
static void
bz2CompressToLog(const Bz2Compress *const this, StringStatic *const debugLog)
{
    strStcFmt(
        debugLog, "{inputSame: %s, done: %s, flushing: %s, avail_in: %u}", cvtBoolToConstZ(this->inputSame),
        cvtBoolToConstZ(this->done), cvtBoolToConstZ(this->flushing), this->stream.avail_in);
}

#define FUNCTION_LOG_BZ2_COMPRESS_TYPE                                                                                             \
    Bz2Compress *
#define FUNCTION_LOG_BZ2_COMPRESS_FORMAT(value, buffer, bufferSize)                                                                \
    FUNCTION_LOG_OBJECT_FORMAT(value, bz2CompressToLog, buffer, bufferSize)

/***********************************************************************************************************************************
Free compression stream
***********************************************************************************************************************************/
static void
bz2CompressFreeResource(THIS_VOID)
{
    THIS(Bz2Compress);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(BZ2_COMPRESS, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    pgbr_bz2_compress_state_free(this->state);
    this->state = NULL;

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Compress data
***********************************************************************************************************************************/
static void
bz2CompressProcess(THIS_VOID, const Buffer *const uncompressed, Buffer *const compressed)
{
    THIS(Bz2Compress);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(BZ2_COMPRESS, this);
        FUNCTION_LOG_PARAM(BUFFER, uncompressed);
        FUNCTION_LOG_PARAM(BUFFER, compressed);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(!this->done);
    ASSERT(compressed != NULL);
    ASSERT(!this->flushing || uncompressed == NULL);
    ASSERT(this->flushing || (!this->inputSame || this->inputAvail != 0));

    // If input is NULL then start flushing
    if (uncompressed == NULL)
    {
        this->inputAvail = 0;
        this->inputPtr = NULL;
        this->flushing = true;
    }
    else if (!this->inputSame)
    {
        this->inputAvail = bufUsed(uncompressed);
        this->inputPtr = bufPtrConst(uncompressed);
    }

    // Run one bz2 compress tick
    size_t written = 0;
    size_t consumed = 0;
    const int result = pgbr_bz2_compress_state_compress(
        this->state, this->inputPtr, this->inputAvail, bufRemainsPtr(compressed), bufRemains(compressed), this->flushing,
        &written, &consumed);

    // Surface libbz2 errors via the legacy classifier.
    bz2Error(result);

    // Set buffer used space
    bufUsedInc(compressed, written);

    // Advance the unconsumed-input cursor
    this->inputAvail -= consumed;
    this->inputPtr += consumed;

    // Mirror availIn into the public substruct so the log formatter and tests see a consistent value.
    this->stream.avail_in = (unsigned int)this->inputAvail;

    // Is compression done?
    if (this->flushing && result == BZ_COMPRESS_STREAM_END)
        this->done = true;

    // Can more input be provided on the next call?
    this->inputSame = this->flushing ? !this->done : this->inputAvail != 0;

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Is compress done?
***********************************************************************************************************************************/
static bool
bz2CompressDone(const THIS_VOID)
{
    THIS(const Bz2Compress);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(BZ2_COMPRESS, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->done);
}

/***********************************************************************************************************************************
Is the same input required on the next process call?
***********************************************************************************************************************************/
static bool
bz2CompressInputSame(const THIS_VOID)
{
    THIS(const Bz2Compress);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(BZ2_COMPRESS, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->inputSame);
}

/**********************************************************************************************************************************/
FN_EXTERN IoFilter *
bz2CompressNew(const int level, const bool raw)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(INT, level);
        (void)raw;                                                  // Raw unsupported
    FUNCTION_LOG_END();

    ASSERT(level >= BZ2_COMPRESS_LEVEL_MIN && level <= BZ2_COMPRESS_LEVEL_MAX);

    OBJ_NEW_BEGIN(Bz2Compress, .childQty = MEM_CONTEXT_QTY_MAX, .callbackQty = 1)
    {
        *this = (Bz2Compress){.state = NULL};

        // Create the Rust streaming compressor
        int32_t errCode = 0;
        this->state = pgbr_bz2_compress_state_new(level, &errCode);

        if (this->state == NULL)
        {
            pgbr_last_error_clear();
            bz2Error(errCode);
        }

        // Set callback to ensure bz2 stream is freed
        memContextCallbackSet(objMemContext(this), bz2CompressFreeResource, this);
    }
    OBJ_NEW_END();

    FUNCTION_LOG_RETURN(
        IO_FILTER,
        ioFilterNewP(
            BZ2_COMPRESS_FILTER_TYPE, this, compressParamList(level, raw), .done = bz2CompressDone, .inOut = bz2CompressProcess,
            .inputSame = bz2CompressInputSame));
}
