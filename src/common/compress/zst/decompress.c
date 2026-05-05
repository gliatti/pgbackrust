/***********************************************************************************************************************************
ZST Decompress

Thin C wrapper over the Rust streaming decompressor in `crates/pgbr-compress::zst::decompress`. The IoFilter object, the
input-cursor state, and the `frameDone` / `done` / `inputSame` flags stay on the C side; the libzstd calls
(`ZSTD_createDStream`, `ZSTD_initDStream`, `ZSTD_decompressStream`, `ZSTD_freeDStream`) are replaced by FFI calls into
libpgbr_ffi.a.
***********************************************************************************************************************************/
#include <build.h>

#ifdef HAVE_LIBZST

#include "common/compress/common.h"
#include "common/compress/zst/common.h"
#include "common/compress/zst/decompress.h"
#include "common/debug.h"
#include "common/io/filter/filter.h"
#include "common/log.h"
#include "common/type/object.h"
#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Object type
***********************************************************************************************************************************/
typedef struct ZstDecompress
{
    void *state;                                                    // Opaque pgbr_compress::zst::decompress::Decompress*
    IoFilter *filter;                                               // Filter interface

    bool inputSame;                                                 // Is the same input required on the next process call?
    size_t inputOffset;                                             // Current offset in input buffer
    bool frameDone;                                                 // Has the current frame completed?
    bool done;                                                      // Is decompression done?
} ZstDecompress;

/***********************************************************************************************************************************
Render as string for logging
***********************************************************************************************************************************/
static void
zstDecompressToLog(const ZstDecompress *const this, StringStatic *const debugLog)
{
    strStcFmt(
        debugLog, "{inputSame: %s, inputOffset: %zu, frameDone %s, done: %s}", cvtBoolToConstZ(this->inputSame), this->inputOffset,
        cvtBoolToConstZ(this->frameDone), cvtBoolToConstZ(this->done));
}

#define FUNCTION_LOG_ZST_DECOMPRESS_TYPE                                                                                           \
    ZstDecompress *
#define FUNCTION_LOG_ZST_DECOMPRESS_FORMAT(value, buffer, bufferSize)                                                              \
    FUNCTION_LOG_OBJECT_FORMAT(value, zstDecompressToLog, buffer, bufferSize)

/***********************************************************************************************************************************
Free decompression context
***********************************************************************************************************************************/
static void
zstDecompressFreeResource(THIS_VOID)
{
    THIS(ZstDecompress);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(ZST_DECOMPRESS, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    pgbr_zst_decompress_state_free(this->state);
    this->state = NULL;

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Decompress data
***********************************************************************************************************************************/
static void
zstDecompressProcess(THIS_VOID, const Buffer *const compressed, Buffer *const decompressed)
{
    THIS(ZstDecompress);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(ZST_DECOMPRESS, this);
        FUNCTION_LOG_PARAM(BUFFER, compressed);
        FUNCTION_LOG_PARAM(BUFFER, decompressed);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(this->state != NULL);
    ASSERT(decompressed != NULL);

    if (compressed == NULL)
    {
        if (!this->frameDone)
            THROW(FormatError, "unexpected eof in compressed data");

        this->done = true;
    }
    else
    {
        const size_t srcAvail = bufUsed(compressed) - this->inputOffset;
        size_t written = 0;
        size_t consumed = 0;
        const size_t hint = pgbr_zst_decompress_state_decompress(
            this->state, bufPtrConst(compressed) + this->inputOffset, srcAvail, bufRemainsPtr(decompressed),
            bufRemains(decompressed), &written, &consumed);

        // Surface libzstd errors via the legacy classifier; `frameDone` flags hint==0.
        this->frameDone = zstError(hint) == 0;

        bufUsedInc(decompressed, written);

        if (consumed < srcAvail)
        {
            this->inputSame = true;
            this->inputOffset += consumed;
        }
        else
        {
            this->inputOffset = 0;
            this->inputSame = false;
        }
    }

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Is decompress done?
***********************************************************************************************************************************/
static bool
zstDecompressDone(const THIS_VOID)
{
    THIS(const ZstDecompress);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ZST_DECOMPRESS, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->done);
}

/***********************************************************************************************************************************
Is the same input required on the next process call?
***********************************************************************************************************************************/
static bool
zstDecompressInputSame(const THIS_VOID)
{
    THIS(const ZstDecompress);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ZST_DECOMPRESS, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->inputSame);
}

/**********************************************************************************************************************************/
FN_EXTERN IoFilter *
zstDecompressNew(const bool raw)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        (void)raw;                                                  // Raw unsupported
    FUNCTION_LOG_END();

    OBJ_NEW_BEGIN(ZstDecompress, .childQty = MEM_CONTEXT_QTY_MAX, .callbackQty = 1)
    {
        *this = (ZstDecompress){.state = NULL};

        // Create the Rust streaming decompressor
        size_t errCode = 0;
        this->state = pgbr_zst_decompress_state_new(&errCode);

        if (this->state == NULL)
        {
            pgbr_last_error_clear();
            zstError(errCode);
        }

        // Set callback to ensure zst context is freed
        memContextCallbackSet(objMemContext(this), zstDecompressFreeResource, this);
    }
    OBJ_NEW_END();

    FUNCTION_LOG_RETURN(
        IO_FILTER,
        ioFilterNewP(
            ZST_DECOMPRESS_FILTER_TYPE, this, decompressParamList(raw), .done = zstDecompressDone, .inOut = zstDecompressProcess,
            .inputSame = zstDecompressInputSame));
}

#endif // HAVE_LIBZST
