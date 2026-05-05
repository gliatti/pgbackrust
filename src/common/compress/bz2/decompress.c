/***********************************************************************************************************************************
BZ2 Decompress

Thin C wrapper over the Rust streaming decompressor in `crates/pgbr-compress::bz2::decompress`. The IoFilter object, debug
logging helpers, and the inputSame / done state machine stay on the C side; the libbz2 calls (`BZ2_bzDecompressInit`,
`BZ2_bzDecompress`, `BZ2_bzDecompressEnd`) are replaced by FFI calls into libpgbr_ffi.a.
***********************************************************************************************************************************/
#include <build.h>

#include <stdio.h>

#include "common/compress/bz2/common.h"
#include "common/compress/bz2/decompress.h"
#include "common/compress/common.h"
#include "common/debug.h"
#include "common/io/filter/filter.h"
#include "common/log.h"
#include "common/macro.h"
#include "common/type/object.h"
#include "pgbr_ffi.h"

// Mirror of libbz2's `BZ_STREAM_END` constant.
#define BZ_DECOMPRESS_STREAM_END                                    4

/***********************************************************************************************************************************
Object type
***********************************************************************************************************************************/
typedef struct Bz2Decompress
{
    void *state;                                                    // Opaque pgbr_compress::bz2::decompress::Decompress*
    size_t inputAvail;                                              // Bytes still unconsumed from the current input buffer
    const unsigned char *inputPtr;                                  // Pointer to the unconsumed slice (into caller's Buffer)

    // Public substruct for `bz2DecompressToLog` testing — only `avail_in` is read/written.
    struct {
        unsigned int avail_in;
    } stream;

    bool inputSame;                                                 // Is the same input required on the next process call?
    bool done;                                                      // Is decompression done?
} Bz2Decompress;

/***********************************************************************************************************************************
Macros for function logging
***********************************************************************************************************************************/
static void
bz2DecompressToLog(const Bz2Decompress *const this, StringStatic *const debugLog)
{
    strStcFmt(
        debugLog, "{inputSame: %s, done: %s, avail_in: %u}", cvtBoolToConstZ(this->inputSame), cvtBoolToConstZ(this->done),
        this->stream.avail_in);
}

#define FUNCTION_LOG_BZ2_DECOMPRESS_TYPE                                                                                            \
    Bz2Decompress *
#define FUNCTION_LOG_BZ2_DECOMPRESS_FORMAT(value, buffer, bufferSize)                                                               \
    FUNCTION_LOG_OBJECT_FORMAT(value, bz2DecompressToLog, buffer, bufferSize)

/***********************************************************************************************************************************
Free decompression stream
***********************************************************************************************************************************/
static void
bz2DecompressFreeResource(THIS_VOID)
{
    THIS(Bz2Decompress);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(BZ2_DECOMPRESS, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    pgbr_bz2_decompress_state_free(this->state);
    this->state = NULL;

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Decompress data
***********************************************************************************************************************************/
static void
bz2DecompressProcess(THIS_VOID, const Buffer *const compressed, Buffer *const uncompressed)
{
    THIS(Bz2Decompress);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(BZ2_DECOMPRESS, this);
        FUNCTION_LOG_PARAM(BUFFER, compressed);
        FUNCTION_LOG_PARAM(BUFFER, uncompressed);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(uncompressed != NULL);

    if (compressed == NULL)
        THROW(FormatError, "unexpected eof in compressed data");

    if (!this->inputSame)
    {
        this->inputAvail = bufUsed(compressed);
        this->inputPtr = bufPtrConst(compressed);
    }

    // Run one bz2 decompress tick
    size_t written = 0;
    size_t consumed = 0;
    const int result = pgbr_bz2_decompress_state_decompress(
        this->state, this->inputPtr, this->inputAvail, bufRemainsPtr(uncompressed), bufRemains(uncompressed), &written, &consumed);

    bz2Error(result);

    bufUsedInc(uncompressed, written);

    this->inputAvail -= consumed;
    this->inputPtr += consumed;

    // Mirror availIn for the public substruct
    this->stream.avail_in = (unsigned int)this->inputAvail;

    this->done = result == BZ_DECOMPRESS_STREAM_END;
    this->inputSame = this->done ? false : this->inputAvail != 0;

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Is decompress done?
***********************************************************************************************************************************/
static bool
bz2DecompressDone(const THIS_VOID)
{
    THIS(const Bz2Decompress);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(BZ2_DECOMPRESS, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->done);
}

/***********************************************************************************************************************************
Is the same input required on the next process call?
***********************************************************************************************************************************/
static bool
bz2DecompressInputSame(const THIS_VOID)
{
    THIS(const Bz2Decompress);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(BZ2_DECOMPRESS, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->inputSame);
}

/**********************************************************************************************************************************/
FN_EXTERN IoFilter *
bz2DecompressNew(const bool raw)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        (void)raw;                                                  // Raw unsupported
    FUNCTION_LOG_END();

    OBJ_NEW_BEGIN(Bz2Decompress, .childQty = MEM_CONTEXT_QTY_MAX, .callbackQty = 1)
    {
        *this = (Bz2Decompress){.state = NULL};

        // Create the Rust streaming decompressor
        int32_t errCode = 0;
        this->state = pgbr_bz2_decompress_state_new(&errCode);

        if (this->state == NULL)
        {
            pgbr_last_error_clear();
            bz2Error(errCode);
        }

        // Set free callback to ensure bz2 context is freed
        memContextCallbackSet(objMemContext(this), bz2DecompressFreeResource, this);
    }
    OBJ_NEW_END();

    FUNCTION_LOG_RETURN(
        IO_FILTER,
        ioFilterNewP(
            BZ2_DECOMPRESS_FILTER_TYPE, this, decompressParamList(raw), .done = bz2DecompressDone, .inOut = bz2DecompressProcess,
            .inputSame = bz2DecompressInputSame));
}
