/***********************************************************************************************************************************
ZST Compress

Thin C wrapper over the Rust streaming compressor in `crates/pgbr-compress::zst::compress`. The IoFilter object, the
`inputSame` / `flushing` / `inputOffset` state machine, and `zstCompressToLog` stay on the C side; the libzstd calls
(`ZSTD_createCStream`, `ZSTD_initCStream`, `ZSTD_compressStream`, `ZSTD_endStream`, `ZSTD_freeCStream`) are replaced by FFI
calls into libpgbr_ffi.a.
***********************************************************************************************************************************/
#include <build.h>

#ifdef HAVE_LIBZST

#include "common/compress/common.h"
#include "common/compress/zst/common.h"
#include "common/compress/zst/compress.h"
#include "common/debug.h"
#include "common/io/filter/filter.h"
#include "common/log.h"
#include "common/type/object.h"
#include "common/type/pack.h"
#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Object type
***********************************************************************************************************************************/
typedef struct ZstCompress
{
    void *state;                                                    // Opaque pgbr_compress::zst::compress::Compress*
    int level;                                                      // Compression level
    IoFilter *filter;                                               // Filter interface

    bool inputSame;                                                 // Is the same input required on the next process call?
    size_t inputOffset;                                             // Current offset in input buffer
    bool flushing;                                                  // Is input complete and flushing in progress?
} ZstCompress;

/***********************************************************************************************************************************
Render as string for logging
***********************************************************************************************************************************/
static void
zstCompressToLog(const ZstCompress *const this, StringStatic *const debugLog)
{
    strStcFmt(
        debugLog, "{level: %d, inputSame: %s, inputOffset: %zu, flushing: %s}", this->level, cvtBoolToConstZ(this->inputSame),
        this->inputOffset, cvtBoolToConstZ(this->flushing));
}

#define FUNCTION_LOG_ZST_COMPRESS_TYPE                                                                                             \
    ZstCompress *
#define FUNCTION_LOG_ZST_COMPRESS_FORMAT(value, buffer, bufferSize)                                                                \
    FUNCTION_LOG_OBJECT_FORMAT(value, zstCompressToLog, buffer, bufferSize)

/***********************************************************************************************************************************
Free compression context
***********************************************************************************************************************************/
static void
zstCompressFreeResource(THIS_VOID)
{
    THIS(ZstCompress);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(ZST_COMPRESS, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    pgbr_zst_compress_state_free(this->state);
    this->state = NULL;

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Compress data
***********************************************************************************************************************************/
static void
zstCompressProcess(THIS_VOID, const Buffer *const uncompressed, Buffer *const compressed)
{
    THIS(ZstCompress);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(ZST_COMPRESS, this);
        FUNCTION_LOG_PARAM(BUFFER, uncompressed);
        FUNCTION_LOG_PARAM(BUFFER, compressed);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(!(this->flushing && !this->inputSame));
    ASSERT(this->state != NULL);
    ASSERT(compressed != NULL);
    ASSERT(!this->flushing || uncompressed == NULL);

    size_t written = 0;

    // If input is NULL then start flushing
    if (uncompressed == NULL)
    {
        this->flushing = true;

        // ZSTD_endStream returns the number of bytes still queued. If non-zero, the C wrapper sets inputSame so the IoFilter
        // framework calls back to drain the rest of the trailer.
        const size_t remaining = pgbr_zst_compress_state_end(this->state, bufRemainsPtr(compressed), bufRemains(compressed),
            &written);
        zstError(remaining);
        this->inputSame = remaining != 0;
    }
    // Else still have input data
    else
    {
        size_t consumed = 0;
        const size_t code = pgbr_zst_compress_state_compress(
            this->state, bufPtrConst(uncompressed) + this->inputOffset, bufUsed(uncompressed) - this->inputOffset,
            bufRemainsPtr(compressed), bufRemains(compressed), &written, &consumed);
        zstError(code);

        // If the input buffer was not entirely consumed then set inputSame and store the offset where processing will restart
        if (consumed < bufUsed(uncompressed) - this->inputOffset)
        {
            this->inputSame = true;
            this->inputOffset += consumed;
        }
        else
        {
            this->inputSame = false;
            this->inputOffset = 0;
        }
    }

    bufUsedInc(compressed, written);

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Is compress done?
***********************************************************************************************************************************/
static bool
zstCompressDone(const THIS_VOID)
{
    THIS(const ZstCompress);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ZST_COMPRESS, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->flushing && !this->inputSame);
}

/***********************************************************************************************************************************
Is the same input required on the next process call?
***********************************************************************************************************************************/
static bool
zstCompressInputSame(const THIS_VOID)
{
    THIS(const ZstCompress);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ZST_COMPRESS, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->inputSame);
}

/**********************************************************************************************************************************/
FN_EXTERN IoFilter *
zstCompressNew(const int level, const bool raw)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(INT, level);
        (void)raw;                                                  // Raw unsupported
    FUNCTION_LOG_END();

    ASSERT(level >= ZST_COMPRESS_LEVEL_MIN && level <= ZST_COMPRESS_LEVEL_MAX);

    OBJ_NEW_BEGIN(ZstCompress, .childQty = MEM_CONTEXT_QTY_MAX, .callbackQty = 1)
    {
        *this = (ZstCompress){.state = NULL, .level = level};

        // Create the Rust streaming compressor
        size_t errCode = 0;
        this->state = pgbr_zst_compress_state_new(level, &errCode);

        if (this->state == NULL)
        {
            pgbr_last_error_clear();
            zstError(errCode);
        }

        // Set callback to ensure zst context is freed
        memContextCallbackSet(objMemContext(this), zstCompressFreeResource, this);
    }
    OBJ_NEW_END();

    FUNCTION_LOG_RETURN(
        IO_FILTER,
        ioFilterNewP(
            ZST_COMPRESS_FILTER_TYPE, this, compressParamList(level, raw), .done = zstCompressDone, .inOut = zstCompressProcess,
            .inputSame = zstCompressInputSame));
}

#endif // HAVE_LIBZST
