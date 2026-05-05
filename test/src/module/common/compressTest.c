/***********************************************************************************************************************************
Test Compression
***********************************************************************************************************************************/
#include <zlib.h>                                                       // For Z_OK, Z_STREAM_END, gzError-test constants and the
                                                                        // legacy_gz* differential helpers — gz/compress.c and
                                                                        // gz/decompress.c no longer #include <zlib.h> after the
                                                                        // Phase 15 / 16 migration, so the test file pulls it
                                                                        // directly.
#include <lz4frame.h>                                                   // For the legacy_lz4Compress differential helper —
                                                                        // lz4/compress.c (Phase 18) no longer includes
                                                                        // lz4frame.h.
#include <bzlib.h>                                                      // For the legacy_bz2Compress differential helper —
                                                                        // bz2/compress.c (Phase 21) no longer includes
                                                                        // bzlib.h.
#ifdef HAVE_LIBZST
#include <zstd.h>                                                       // For the legacy_zstCompress differential helper —
                                                                        // zst/compress.c (Phase 24) no longer includes
                                                                        // zstd.h.
#endif

#include "common/io/bufferRead.h"
#include "common/io/bufferWrite.h"
#include "common/io/filter/group.h"
#include "common/io/io.h"
#include "common/type/pack.h"
#include "storage/posix/storage.h"

/***********************************************************************************************************************************
Differential helpers — rebuild the compress / decompress parameter Pack via direct `pckWrite*` calls (the legacy
`compressParamList` / `decompressParamList` body before Phase 13 routed serialization through Rust). Used to compare against the
new Rust-backed shim over thousands of `(level, raw)` combinations.

`legacy_gzCompress` mirrors the pre-Phase-15 body of `gzCompressNew` / `gzCompressProcess` — direct libz calls with the same
`deflateInit2` parameters (`memLevel = 9`, `Z_DEFAULT_STRATEGY`, `windowBits = 15` for raw / `31` for gzip). Used by the gz
differential to assert that the new FFI path produces byte-identical output. zlib's encoder is deterministic given fixed
parameters, so a one-shot `Z_FINISH` deflate produces the same bytes as the streaming `Z_NO_FLUSH` + `Z_FINISH` chain the
IoFilter wrapper drives — `Z_NO_FLUSH` does not introduce block boundaries, only `Z_FINISH` (called once at the end) does.
***********************************************************************************************************************************/
static Buffer *
legacy_gzCompress(const int level, const bool raw, const Buffer *const input)
{
    // Output sizing: `deflateBound` would be tighter but it requires a live `z_stream`; budget generously to avoid Z_BUF_ERROR
    // — for raw deflate the worst-case overhead per 16 KiB block is small, so `2 * input + 256` is more than enough for any
    // input size we drive in the differential.
    Buffer *const output = bufNew(bufUsed(input) * 2 + 256);

    z_stream stream = {.zalloc = NULL, .zfree = NULL, .opaque = NULL};

    int ret = deflateInit2(&stream, level, Z_DEFLATED, (raw ? 0 : WANT_GZ) | WINDOW_BITS, 9, Z_DEFAULT_STRATEGY);
    ASSERT(ret == Z_OK);

    // bufPtrConst returns `const uint8_t *`; libz declares `next_in` as non-const but only reads from it (the legacy `gzCompress`
    // module includes the same disclaimer in a comment). Cast through `uintptr_t` so `-Wcast-qual` does not flag the deliberate
    // const-strip.
    stream.avail_in = (uInt)bufUsed(input);
    stream.next_in = (Bytef *)(uintptr_t)bufPtrConst(input);
    stream.avail_out = (uInt)bufSize(output);
    stream.next_out = bufPtr(output);

    ret = deflate(&stream, Z_FINISH);
    ASSERT(ret == Z_STREAM_END);

    bufUsedSet(output, bufSize(output) - stream.avail_out);

    deflateEnd(&stream);

    return output;
}

// `legacy_gzDecompress` mirrors the pre-Phase-16 body of `gzDecompressNew` / `gzDecompressProcess` — direct libz calls with the
// same `inflateInit2` parameters (`windowBits = 15` for raw / `31` for gzip). Used by the gz decompress differential to assert
// that the new FFI path produces byte-identical output.
static Buffer *
legacy_gzDecompress(const bool raw, const Buffer *const input)
{
    // Output sizing: gzip's typical compression ratio is at most ~1024x for highly redundant input, but realistic inputs the
    // differential test feeds are random-ish bytes that don't compress well, so a small constant multiplier is plenty. The
    // ASSERT below catches the rare overflow case immediately.
    Buffer *const output = bufNew(bufUsed(input) * 64 + 4096);

    z_stream stream = {.zalloc = NULL, .zfree = NULL, .opaque = NULL};

    int ret = inflateInit2(&stream, (raw ? 0 : WANT_GZ) | WINDOW_BITS);
    ASSERT(ret == Z_OK);

    stream.avail_in = (uInt)bufUsed(input);
    stream.next_in = (Bytef *)(uintptr_t)bufPtrConst(input);
    stream.avail_out = (uInt)bufSize(output);
    stream.next_out = bufPtr(output);

    ret = inflate(&stream, Z_NO_FLUSH);
    ASSERT(ret == Z_STREAM_END);

    bufUsedSet(output, bufSize(output) - stream.avail_out);

    inflateEnd(&stream);

    return output;
}

// `legacy_zstCompress` mirrors the pre-Phase-24 body of `zstCompressNew` / `zstCompressProcess` — direct libzstd calls with the
// same level. One-shot compression; libzstd is deterministic given fixed level, so the new IoFilter path and this helper
// produce byte-identical frames.
#ifdef HAVE_LIBZST
static Buffer *
legacy_zstCompress(const int level, const Buffer *const input)
{
    ZSTD_CStream *const ctx = ZSTD_createCStream();
    ASSERT(ctx != NULL);
    size_t ret = ZSTD_initCStream(ctx, level);
    ASSERT(!ZSTD_isError(ret));

    Buffer *const output = bufNew(bufUsed(input) * 2 + 4096);

    ZSTD_inBuffer in = {.src = bufPtrConst(input), .size = bufUsed(input), .pos = 0};
    ZSTD_outBuffer out = {.dst = bufPtr(output), .size = bufSize(output), .pos = 0};

    ret = ZSTD_compressStream(ctx, &out, &in);
    ASSERT(!ZSTD_isError(ret));
    ASSERT(in.pos == in.size);

    // Flush trailer; loop until ZSTD_endStream returns 0.
    do
    {
        ret = ZSTD_endStream(ctx, &out);
        ASSERT(!ZSTD_isError(ret));
    }
    while (ret != 0);

    bufUsedSet(output, out.pos);

    ZSTD_freeCStream(ctx);

    return output;
}
#endif

// `legacy_bz2Decompress` mirrors the pre-Phase-22 body of `bz2DecompressNew` / `bz2DecompressProcess` — direct libbz2 calls.
// One-shot decompression; both the new IoFilter path and this helper recover the original plaintext byte-for-byte because
// libbz2's frame decoder is fully deterministic.
static Buffer *
legacy_bz2Decompress(const Buffer *const input)
{
    bz_stream stream = {.bzalloc = NULL, .bzfree = NULL, .opaque = NULL};

    int ret = BZ2_bzDecompressInit(&stream, 0, 0);
    ASSERT(ret == BZ_OK);

    Buffer *const output = bufNew(bufUsed(input) * 64 + 4096);

    stream.avail_in = (unsigned int)bufUsed(input);
    stream.next_in = (char *)(uintptr_t)bufPtrConst(input);
    stream.avail_out = (unsigned int)bufSize(output);
    stream.next_out = (char *)bufPtr(output);

    ret = BZ2_bzDecompress(&stream);
    ASSERT(ret == BZ_STREAM_END);

    bufUsedSet(output, bufSize(output) - stream.avail_out);

    BZ2_bzDecompressEnd(&stream);

    return output;
}

// `legacy_bz2Compress` mirrors the pre-Phase-21 body of `bz2CompressNew` / `bz2CompressProcess` — direct libbz2 calls with the
// same parameters (level, workFactor=0, verbosity=0). One-shot compression; libbz2 is deterministic given fixed parameters.
static Buffer *
legacy_bz2Compress(const int level, const Buffer *const input)
{
    bz_stream stream = {.bzalloc = NULL, .bzfree = NULL, .opaque = NULL};

    int ret = BZ2_bzCompressInit(&stream, level, 0, 0);
    ASSERT(ret == BZ_OK);

    Buffer *const output = bufNew(bufUsed(input) * 2 + 4096);

    stream.avail_in = (unsigned int)bufUsed(input);
    stream.next_in = (char *)(uintptr_t)bufPtrConst(input);
    stream.avail_out = (unsigned int)bufSize(output);
    stream.next_out = (char *)bufPtr(output);

    ret = BZ2_bzCompress(&stream, BZ_FINISH);
    ASSERT(ret == BZ_STREAM_END);

    bufUsedSet(output, bufSize(output) - stream.avail_out);

    BZ2_bzCompressEnd(&stream);

    return output;
}

// `legacy_lz4Decompress` mirrors the pre-Phase-19 body of `lz4DecompressNew` / `lz4DecompressProcess` — direct LZ4F calls with
// no special prefs (the decoder detects them from the frame header). One-shot decompression; both the new IoFilter path and
// this helper recover the original plaintext byte-for-byte because liblz4's frame decoder is fully deterministic.
static Buffer *
legacy_lz4Decompress(const Buffer *const input)
{
    LZ4F_decompressionContext_t ctx;
    size_t ret = LZ4F_createDecompressionContext(&ctx, LZ4F_VERSION);
    ASSERT(!LZ4F_isError(ret));

    Buffer *const output = bufNew(bufUsed(input) * 64 + 4096);

    size_t srcSize = bufUsed(input);
    size_t dstSize = bufRemains(output);

    ret = LZ4F_decompress(ctx, bufRemainsPtr(output), &dstSize, bufPtrConst(input), &srcSize, NULL);
    ASSERT(!LZ4F_isError(ret));
    ASSERT(ret == 0);                                                   // Frame fully consumed in one tick

    bufUsedInc(output, dstSize);

    LZ4F_freeDecompressionContext(ctx);

    return output;
}

// `legacy_lz4Compress` mirrors the pre-Phase-18 body of `lz4CompressNew` / `lz4CompressProcess` — direct LZ4F calls with the same
// preferences (compressionLevel, contentChecksumFlag toggled by `raw`). One-shot compression; both the new IoFilter path and
// this helper output byte-identical frames because liblz4 is deterministic given fixed prefs and a fixed `LZ4F_VERSION`.
static Buffer *
legacy_lz4Compress(const int level, const bool raw, const Buffer *const input)
{
    LZ4F_preferences_t prefs =
    {
        .compressionLevel = level,
        .frameInfo = {.contentChecksumFlag = raw ? LZ4F_noContentChecksum : LZ4F_contentChecksumEnabled},
    };

    LZ4F_compressionContext_t ctx;
    size_t ret = LZ4F_createCompressionContext(&ctx, LZ4F_VERSION);
    ASSERT(!LZ4F_isError(ret));

    const size_t bound = LZ4F_compressBound(bufUsed(input), &prefs);
    ASSERT(!LZ4F_isError(bound));

    Buffer *const output = bufNew(bound + 32);

    size_t written = LZ4F_compressBegin(ctx, bufRemainsPtr(output), bufRemains(output), &prefs);
    ASSERT(!LZ4F_isError(written));
    bufUsedInc(output, written);

    if (bufUsed(input) > 0)
    {
        written = LZ4F_compressUpdate(
            ctx, bufRemainsPtr(output), bufRemains(output), bufPtrConst(input), bufUsed(input), NULL);
        ASSERT(!LZ4F_isError(written));
        bufUsedInc(output, written);
    }

    written = LZ4F_compressEnd(ctx, bufRemainsPtr(output), bufRemains(output), NULL);
    ASSERT(!LZ4F_isError(written));
    bufUsedInc(output, written);

    LZ4F_freeCompressionContext(ctx);

    return output;
}

static Pack *
legacy_compressParamList(const int level, const bool raw)
{
    Pack *result;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        PackWrite *const packWrite = pckWriteNewP();

        pckWriteI32P(packWrite, level);
        pckWriteBoolP(packWrite, raw);
        pckWriteEndP(packWrite);

        result = pckMove(pckWriteResult(packWrite), memContextPrior());
    }
    MEM_CONTEXT_TEMP_END();

    return result;
}

static Pack *
legacy_decompressParamList(const bool raw)
{
    Pack *result;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        PackWrite *const packWrite = pckWriteNewP();

        pckWriteBoolP(packWrite, raw);
        pckWriteEndP(packWrite);

        result = pckMove(pckWriteResult(packWrite), memContextPrior());
    }
    MEM_CONTEXT_TEMP_END();

    return result;
}

/***********************************************************************************************************************************
Compress data
***********************************************************************************************************************************/
static Buffer *
testCompress(IoFilter *compress, Buffer *decompressed, size_t inputSize, size_t outputSize)
{
    Buffer *compressed = bufNew(1024 * 1024);
    size_t inputTotal = 0;
    ioBufferSizeSet(outputSize);

    IoWrite *write = ioBufferWriteNew(compressed);
    ioFilterGroupAdd(ioWriteFilterGroup(write), compress);
    ioWriteOpen(write);

    // Compress input data
    while (inputTotal < bufSize(decompressed))
    {
        // Generate the input buffer based on input size. This breaks the data up into chunks as it would be in a real scenario.
        Buffer *input = bufNewC(
            bufPtr(decompressed) + inputTotal,
            inputSize > bufSize(decompressed) - inputTotal ? bufSize(decompressed) - inputTotal : inputSize);

        ioWrite(write, input);

        inputTotal += bufUsed(input);
        bufFree(input);
    }

    ioWriteClose(write);
    ioFilterFree(compress);

    return compressed;
}

/***********************************************************************************************************************************
Decompress data
***********************************************************************************************************************************/
static Buffer *
testDecompress(IoFilter *decompress, Buffer *compressed, size_t inputSize, size_t outputSize)
{
    Buffer *decompressed = bufNew(1024 * 1024);
    Buffer *output = bufNew(outputSize);
    ioBufferSizeSet(inputSize);

    IoRead *read = ioBufferReadNew(compressed);
    ioFilterGroupAdd(ioReadFilterGroup(read), decompress);
    ioReadOpen(read);

    while (!ioReadEof(read))
    {
        ioRead(read, output);
        bufCat(decompressed, output);
        bufUsedZero(output);
    }

    ioReadClose(read);
    bufFree(output);
    ioFilterFree(decompress);

    return decompressed;
}

/***********************************************************************************************************************************
Standard test suite to be applied to all compression types
***********************************************************************************************************************************/
static void
testSuite(CompressType type, const char *decompressCmd, size_t rawDelta)
{
    const char *simpleData = "A simple string";
    Buffer *compressed = NULL;
    Buffer *compressedRaw = NULL;
    Buffer *decompressed = bufNewC(simpleData, strlen(simpleData));

    PackWrite *packWrite = pckWriteNewP();
    pckWriteI32P(packWrite, 1);
    pckWriteBoolP(packWrite, false);
    pckWriteEndP(packWrite);

    // Create default storage object for testing
    Storage *storageTest = storagePosixNewP(TEST_PATH_STR, .write = true);

    TEST_TITLE("simple data");

    TEST_ASSIGN(
        compressed,
        testCompress(
            compressFilterPack(compressHelperLocal[type].compressType, pckWriteResult(packWrite)), decompressed, 1024,
            256 * 1024 * 1024),
        "simple data - compress large in/large out buffer");

    packWrite = pckWriteNewP();
    pckWriteI32P(packWrite, 1);
    pckWriteBoolP(packWrite, true);
    pckWriteEndP(packWrite);

    TEST_ASSIGN(
        compressedRaw,
        testCompress(
            compressFilterPack(compressHelperLocal[type].compressType, pckWriteResult(packWrite)), decompressed, 1024,
            1024),
        "simple data - compress large in/large out buffer (raw)");

    TEST_RESULT_UINT(bufUsed(compressed) - rawDelta, bufUsed(compressedRaw), "compare to raw");

    // -------------------------------------------------------------------------------------------------------------------------
    TEST_TITLE("compressed output can be decompressed with command-line tool");

    storagePutP(storageNewWriteP(storageTest, STRDEF("test.cmp")), compressed);
    HRN_SYSTEM_FMT("%s " TEST_PATH "/test.cmp > " TEST_PATH "/test.out 2> /dev/null", decompressCmd);
    TEST_RESULT_BOOL(bufEq(decompressed, storageGetP(storageNewReadP(storageTest, STRDEF("test.out")))), true, "check output");

    TEST_RESULT_BOOL(
        bufEq(compressed, testCompress(compressFilterP(type, 1), decompressed, 1024, 1)), true,
        "simple data - compress large in/small out buffer");

    TEST_RESULT_BOOL(
        bufEq(compressed, testCompress(compressFilterP(type, 1), decompressed, 1, 1024)), true,
        "simple data - compress small in/large out buffer");

    TEST_RESULT_BOOL(
        bufEq(compressed, testCompress(compressFilterP(type, 1), decompressed, 1, 1)), true,
        "simple data - compress small in/small out buffer");

    TEST_RESULT_BOOL(
        bufEq(compressedRaw, testCompress(compressFilterP(type, 1, .raw = true), decompressed, 1, 1)), true,
        "simple data - compress small in/small out buffer (raw)");

    packWrite = pckWriteNewP();
    pckWriteBoolP(packWrite, false);
    pckWriteEndP(packWrite);

    TEST_RESULT_BOOL(
        bufEq(
            decompressed,
            testDecompress(
                compressFilterPack(compressHelperLocal[type].decompressType, pckWriteResult(packWrite)), compressed, 1024, 1024)),
        true, "simple data - decompress large in/small out buffer");

    packWrite = pckWriteNewP();
    pckWriteBoolP(packWrite, true);
    pckWriteEndP(packWrite);

    TEST_RESULT_BOOL(
        bufEq(
            decompressed,
            testDecompress(
                compressFilterPack(
                    compressHelperLocal[type].decompressType, pckWriteResult(packWrite)), compressedRaw, 1024, 1024)),
        true, "simple data - decompress large in/large out buffer (raw)");

    TEST_RESULT_BOOL(
        bufEq(decompressed, testDecompress(decompressFilterP(type), compressed, 1024, 1)), true,
        "simple data - decompress large in/small out buffer");

    TEST_RESULT_BOOL(
        bufEq(decompressed, testDecompress(decompressFilterP(type), compressed, 1, 1024)), true,
        "simple data - decompress small in/large out buffer");

    TEST_RESULT_BOOL(
        bufEq(decompressed, testDecompress(decompressFilterP(type), compressed, 1, 1)), true,
        "simple data - decompress small in/small out buffer");

    // -------------------------------------------------------------------------------------------------------------------------
    TEST_TITLE("error on no compression data");

    TEST_ERROR(testDecompress(decompressFilterP(type), bufNew(0), 1, 1), FormatError, "unexpected eof in compressed data");

    // -------------------------------------------------------------------------------------------------------------------------
    TEST_TITLE("error on truncated compression data");

    Buffer *truncated = bufNew(0);
    bufCatSub(truncated, compressed, 0, bufUsed(compressed) - 1);

    TEST_RESULT_UINT(bufUsed(truncated), bufUsed(compressed) - 1, "check truncated buffer size");
    TEST_ERROR(testDecompress(decompressFilterP(type), truncated, 512, 512), FormatError, "unexpected eof in compressed data");

    // -------------------------------------------------------------------------------------------------------------------------
    TEST_TITLE("compress a large non-zero input buffer into small output buffer");

    decompressed = bufNew(1024 * 1024 - 1);
    uint8_t *chr = bufPtr(decompressed);

    // Step through the buffer, setting the individual bytes in a simple pattern (visible ASCII characters, DEC 32 - 126), to make
    // sure that we fill the compression library's small output buffer
    for (size_t chrIdx = 0; chrIdx < bufSize(decompressed); chrIdx++)
        chr[chrIdx] = (uint8_t)(chrIdx % 94 + 32);

    bufUsedSet(decompressed, bufSize(decompressed));

    TEST_ASSIGN(
        compressed, testCompress(compressFilterP(type, 3), decompressed, bufSize(decompressed), 32),
        "non-zero data - compress large in/small out buffer");

    TEST_RESULT_BOOL(
        bufEq(decompressed, testDecompress(decompressFilterP(type), compressed, bufSize(compressed), 1024 * 256)), true,
        "non-zero data - decompress large in/small out buffer");
}

/***********************************************************************************************************************************
Test Run
***********************************************************************************************************************************/
static void
testRun(void)
{
    FUNCTION_HARNESS_VOID();

    // *****************************************************************************************************************************
    if (testBegin("gz"))
    {
        // Run standard test suite
        testSuite(compressTypeGz, "gzip -dc", 12);

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("gzError()");

        TEST_RESULT_INT(gzError(Z_OK), Z_OK, "check ok");
        TEST_RESULT_INT(gzError(Z_STREAM_END), Z_STREAM_END, "check stream end");
        TEST_ERROR(gzError(Z_NEED_DICT), AssertError, "zlib threw error: [2] need dictionary");
        TEST_ERROR(gzError(Z_ERRNO), AssertError, "zlib threw error: [-1] file error");
        TEST_ERROR(gzError(Z_STREAM_ERROR), FormatError, "zlib threw error: [-2] stream error");
        TEST_ERROR(gzError(Z_DATA_ERROR), FormatError, "zlib threw error: [-3] data error");
        TEST_ERROR(gzError(Z_MEM_ERROR), MemoryError, "zlib threw error: [-4] insufficient memory");
        TEST_ERROR(gzError(Z_BUF_ERROR), AssertError, "zlib threw error: [-5] no space in buffer");
        TEST_ERROR(gzError(Z_VERSION_ERROR), FormatError, "zlib threw error: [-6] incompatible version");
        TEST_ERROR(gzError(999), AssertError, "zlib threw error: [999] unknown error");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("gzDecompressToLog() and gzCompressToLog()");

        char buffer[STACK_TRACE_PARAM_MAX];

        GzDecompress *decompress = (GzDecompress *)ioFilterDriver(gzDecompressNew(false));

        TEST_RESULT_VOID(FUNCTION_LOG_OBJECT_FORMAT(decompress, gzDecompressToLog, buffer, sizeof(buffer)), "gzDecompressToLog");
        TEST_RESULT_Z(buffer, "{inputSame: false, done: false, availIn: 0}", "check log");

        decompress->inputSame = true;
        decompress->done = true;

        TEST_RESULT_VOID(FUNCTION_LOG_OBJECT_FORMAT(decompress, gzDecompressToLog, buffer, sizeof(buffer)), "gzDecompressToLog");
        TEST_RESULT_Z(buffer, "{inputSame: true, done: true, availIn: 0}", "check log");

        GzCompress *compress = (GzCompress *)ioFilterDriver(gzCompressNew(1, false));

        TEST_RESULT_VOID(FUNCTION_LOG_OBJECT_FORMAT(compress, gzCompressToLog, buffer, sizeof(buffer)), "gzCompressToLog");
        TEST_RESULT_Z(buffer, "{inputSame: false, done: false, flushing: false, availIn: 0}", "check log");

        compress->inputSame = true;
        compress->flushing = true;
        compress->done = true;
        compress->inputAvail = 7;

        TEST_RESULT_VOID(FUNCTION_LOG_OBJECT_FORMAT(compress, gzCompressToLog, buffer, sizeof(buffer)), "gzCompressToLog");
        TEST_RESULT_Z(buffer, "{inputSame: true, done: true, flushing: true, availIn: 7}", "check log");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("gzCompress differential vs direct zlib (10000+ inputs)");

        // Generate 10 000 random `(level, raw, input)` triples with a deterministic LCG so the test is reproducible. For each
        // triple, compress through the new FFI path (`compressFilterP(compressTypeGz, level, .raw = raw)`) and through
        // `legacy_gzCompress` (direct libz with the same parameters). Both paths must produce byte-identical output — zlib's
        // encoder is deterministic, and the legacy path is byte-for-byte what the pre-Phase-15 C code did.
        uint64_t lcgState = UINT64_C(0xDEADBEEFCAFEBEEF);
        unsigned int comparisons = 0;

        for (unsigned int iter = 0; iter < 10000; iter++)
        {
            lcgState = lcgState * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);

            // Random length in [1, 1024]. The zero-byte case is covered separately by `pgbr-compress`'s
            // `roundtrip_zero_byte_input` Rust test; including it here would be confounded by `testCompress` reading from the
            // input buffer's allocated size (not its `used` count), so a 0-byte input ends up streaming a single uninitialized
            // byte through the filter and producing a non-comparable output.
            const size_t len = (size_t)((lcgState >> 32) & 0x3FF) + 1;      // 1..1024 bytes
            const int level = (int)(((lcgState >> 24) & 0xFF) % 11) - 1;    // -1..9
            const bool raw = ((lcgState >> 16) & 1) == 0;

            Buffer *const input = bufNew(len);
            for (size_t i = 0; i < len; i++)
            {
                lcgState = lcgState * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
                bufPtr(input)[i] = (uint8_t)(lcgState >> 56);
            }
            bufUsedSet(input, len);

            Buffer *const newOut = testCompress(
                compressFilterP(compressTypeGz, level, .raw = raw), input, len, len * 2 + 256);
            Buffer *const legacyOut = legacy_gzCompress(level, raw, input);

            if (!bufEq(newOut, legacyOut))
            {
                TEST_ERROR_FMT(
                    THROW_FMT(AssertError, "differential mismatch"),
                    AssertError,
                    "gzCompress(level=%d, raw=%d, len=%zu) iter=%u newSize=%zu legacySize=%zu", level, (int)raw, len, iter,
                    bufUsed(newOut), bufUsed(legacyOut));
            }

            bufFree(input);
            bufFree(newOut);
            bufFree(legacyOut);

            comparisons++;
        }

        TEST_RESULT_UINT(comparisons, 10000, "10k differential gzCompress inputs all byte-identical");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("gzDecompress differential vs direct zlib (10000+ inputs)");

        // Generate 10 000 random `(raw, plaintext)` pairs, compress each through `compressFilterP(compressTypeGz, ...)` (so we
        // know the compressed bytes are valid) and decompress through both the new FFI path (`decompressFilterP`) and a
        // `legacy_gzDecompress` helper (direct libz with the same parameters). The decompressed output must round-trip the
        // original plaintext byte-for-byte AND the two paths must agree.
        lcgState = UINT64_C(0xDECAFC0FFEEFACED);
        unsigned int decompComparisons = 0;

        for (unsigned int iter = 0; iter < 10000; iter++)
        {
            lcgState = lcgState * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);

            const size_t len = (size_t)((lcgState >> 32) & 0x3FF) + 1;      // 1..1024 bytes
            const bool raw = ((lcgState >> 16) & 1) == 0;

            Buffer *const plaintext = bufNew(len);
            for (size_t i = 0; i < len; i++)
            {
                lcgState = lcgState * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
                bufPtr(plaintext)[i] = (uint8_t)(lcgState >> 56);
            }
            bufUsedSet(plaintext, len);

            // Use the (already-validated) Phase 15 compressor to produce the input stream — this exercises both phases with
            // the same dataset, and whatever compressed bytes come out are necessarily decodable by both decompressors.
            Buffer *const compressedStream = testCompress(
                compressFilterP(compressTypeGz, 6, .raw = raw), plaintext, len, len * 2 + 256);

            Buffer *const newOut = testDecompress(decompressFilterP(compressTypeGz, .raw = raw), compressedStream, len, len + 1);
            Buffer *const legacyOut = legacy_gzDecompress(raw, compressedStream);

            if (!bufEq(newOut, plaintext) || !bufEq(legacyOut, plaintext) || !bufEq(newOut, legacyOut))
            {
                TEST_ERROR_FMT(
                    THROW_FMT(AssertError, "differential mismatch"),
                    AssertError,
                    "gzDecompress(raw=%d, len=%zu) iter=%u newSize=%zu legacySize=%zu plaintextSize=%zu", (int)raw, len, iter,
                    bufUsed(newOut), bufUsed(legacyOut), bufUsed(plaintext));
            }

            bufFree(plaintext);
            bufFree(compressedStream);
            bufFree(newOut);
            bufFree(legacyOut);

            decompComparisons++;
        }

        TEST_RESULT_UINT(decompComparisons, 10000, "10k differential gzDecompress inputs all byte-identical");
    }

    // *****************************************************************************************************************************
    if (testBegin("bz2"))
    {
        // Run standard test suite
        testSuite(compressTypeBz2, "bzip2 -dc", 0);

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("bz2Error()");

        TEST_RESULT_INT(bz2Error(BZ_OK), BZ_OK, "check ok");
        TEST_RESULT_INT(bz2Error(BZ_RUN_OK), BZ_RUN_OK, "check run ok");
        TEST_RESULT_INT(bz2Error(BZ_FLUSH_OK), BZ_FLUSH_OK, "check flush ok");
        TEST_RESULT_INT(bz2Error(BZ_FINISH_OK), BZ_FINISH_OK, "check finish ok");
        TEST_RESULT_INT(bz2Error(BZ_STREAM_END), BZ_STREAM_END, "check stream end");
        TEST_ERROR(bz2Error(BZ_SEQUENCE_ERROR), AssertError, "bz2 error: [-1] sequence error");
        TEST_ERROR(bz2Error(BZ_PARAM_ERROR), AssertError, "bz2 error: [-2] parameter error");
        TEST_ERROR(bz2Error(BZ_MEM_ERROR), MemoryError, "bz2 error: [-3] memory error");
        TEST_ERROR(bz2Error(BZ_DATA_ERROR), FormatError, "bz2 error: [-4] data error");
        TEST_ERROR(bz2Error(BZ_DATA_ERROR_MAGIC), FormatError, "bz2 error: [-5] data error magic");
        TEST_ERROR(bz2Error(BZ_IO_ERROR), AssertError, "bz2 error: [-6] io error");
        TEST_ERROR(bz2Error(BZ_UNEXPECTED_EOF), AssertError, "bz2 error: [-7] unexpected eof");
        TEST_ERROR(bz2Error(BZ_OUTBUFF_FULL), AssertError, "bz2 error: [-8] outbuff full");
        TEST_ERROR(bz2Error(BZ_CONFIG_ERROR), AssertError, "bz2 error: [-9] config error");
        TEST_ERROR(bz2Error(-999), AssertError, "bz2 error: [-999] unknown error");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("bz2DecompressToLog() and bz2CompressToLog()");

        char buffer[STACK_TRACE_PARAM_MAX];

        Bz2Compress *compress = (Bz2Compress *)ioFilterDriver(bz2CompressNew(1, false));

        compress->stream.avail_in = 999;

        TEST_RESULT_VOID(FUNCTION_LOG_OBJECT_FORMAT(compress, bz2CompressToLog, buffer, sizeof(buffer)), "bz2CompressToLog");
        TEST_RESULT_Z(buffer, "{inputSame: false, done: false, flushing: false, avail_in: 999}", "check log");

        Bz2Decompress *decompress = (Bz2Decompress *)ioFilterDriver(bz2DecompressNew(false));

        decompress->inputSame = true;
        decompress->done = true;

        TEST_RESULT_VOID(FUNCTION_LOG_OBJECT_FORMAT(decompress, bz2DecompressToLog, buffer, sizeof(buffer)), "bz2DecompressToLog");
        TEST_RESULT_Z(buffer, "{inputSame: true, done: true, avail_in: 0}", "check log");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("bz2Compress differential vs direct libbz2 (10000+ inputs)");

        // 10 000 random `(level, plaintext)` pairs. libbz2 is deterministic given fixed level + workFactor=0 + verbosity=0, so
        // the new FFI path and `legacy_bz2Compress` (direct libbz2 calls with the same parameters) must produce byte-identical
        // frames.
        uint64_t bz2LcgState = UINT64_C(0xB22B22B22B22B22B);
        unsigned int bz2Comparisons = 0;

        for (unsigned int iter = 0; iter < 10000; iter++)
        {
            bz2LcgState = bz2LcgState * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);

            const size_t bz2Len = (size_t)((bz2LcgState >> 32) & 0x3FF) + 1;            // 1..1024 bytes
            const int bz2Level = (int)(((bz2LcgState >> 24) & 0xFF) % 9) + 1;           // 1..9

            Buffer *const bz2Input = bufNew(bz2Len);
            for (size_t i = 0; i < bz2Len; i++)
            {
                bz2LcgState = bz2LcgState * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
                bufPtr(bz2Input)[i] = (uint8_t)(bz2LcgState >> 56);
            }
            bufUsedSet(bz2Input, bz2Len);

            Buffer *const bz2NewOut = testCompress(
                compressFilterP(compressTypeBz2, bz2Level), bz2Input, bz2Len, bz2Len * 2 + 4096);
            Buffer *const bz2LegacyOut = legacy_bz2Compress(bz2Level, bz2Input);

            if (!bufEq(bz2NewOut, bz2LegacyOut))
            {
                TEST_ERROR_FMT(
                    THROW_FMT(AssertError, "differential mismatch"),
                    AssertError,
                    "bz2Compress(level=%d, len=%zu) iter=%u newSize=%zu legacySize=%zu", bz2Level, bz2Len, iter,
                    bufUsed(bz2NewOut), bufUsed(bz2LegacyOut));
            }

            bufFree(bz2Input);
            bufFree(bz2NewOut);
            bufFree(bz2LegacyOut);

            bz2Comparisons++;
        }

        TEST_RESULT_UINT(bz2Comparisons, 10000, "10k differential bz2Compress inputs all byte-identical");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("bz2Decompress differential vs direct libbz2 (10000+ inputs)");

        // 10 000 random plaintexts. Compress through Phase 21 then decompress through both the new FFI path and
        // `legacy_bz2Decompress`; both must recover the original plaintext byte-for-byte.
        uint64_t bz2DcLcg = UINT64_C(0x88BB22DD44CC66AA);
        unsigned int bz2DcComparisons = 0;

        for (unsigned int iter = 0; iter < 10000; iter++)
        {
            bz2DcLcg = bz2DcLcg * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);

            const size_t bz2DcLen = (size_t)((bz2DcLcg >> 32) & 0x3FF) + 1;
            const int bz2DcLevel = (int)(((bz2DcLcg >> 24) & 0xFF) % 9) + 1;

            Buffer *const bz2DcPlaintext = bufNew(bz2DcLen);
            for (size_t i = 0; i < bz2DcLen; i++)
            {
                bz2DcLcg = bz2DcLcg * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
                bufPtr(bz2DcPlaintext)[i] = (uint8_t)(bz2DcLcg >> 56);
            }
            bufUsedSet(bz2DcPlaintext, bz2DcLen);

            Buffer *const bz2DcCompressed = testCompress(
                compressFilterP(compressTypeBz2, bz2DcLevel), bz2DcPlaintext, bz2DcLen, bz2DcLen * 2 + 4096);

            Buffer *const bz2DcNewOut = testDecompress(
                decompressFilterP(compressTypeBz2), bz2DcCompressed, bz2DcLen, bz2DcLen + 1);
            Buffer *const bz2DcLegacyOut = legacy_bz2Decompress(bz2DcCompressed);

            if (!bufEq(bz2DcNewOut, bz2DcPlaintext) || !bufEq(bz2DcLegacyOut, bz2DcPlaintext) ||
                !bufEq(bz2DcNewOut, bz2DcLegacyOut))
            {
                TEST_ERROR_FMT(
                    THROW_FMT(AssertError, "differential mismatch"),
                    AssertError,
                    "bz2Decompress(level=%d, len=%zu) iter=%u newSize=%zu legacySize=%zu plaintextSize=%zu", bz2DcLevel, bz2DcLen,
                    iter, bufUsed(bz2DcNewOut), bufUsed(bz2DcLegacyOut), bufUsed(bz2DcPlaintext));
            }

            bufFree(bz2DcPlaintext);
            bufFree(bz2DcCompressed);
            bufFree(bz2DcNewOut);
            bufFree(bz2DcLegacyOut);

            bz2DcComparisons++;
        }

        TEST_RESULT_UINT(bz2DcComparisons, 10000, "10k differential bz2Decompress inputs all byte-identical");
    }

    // *****************************************************************************************************************************
    if (testBegin("lz4"))
    {
        // Run standard test suite
        testSuite(compressTypeLz4, "lz4 -dc", 4);

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("lz4Error()");

        TEST_RESULT_UINT(lz4Error(0), 0, "check success");
        TEST_ERROR(lz4Error((size_t)-2), FormatError, "lz4 error: [-2] ERROR_maxBlockSize_invalid");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("lz4DecompressToLog() and lz4CompressToLog()");

        char buffer[STACK_TRACE_PARAM_MAX];

        Lz4Compress *compress = (Lz4Compress *)ioFilterDriver(lz4CompressNew(7, false));

        compress->inputSame = true;
        compress->flushing = true;

        TEST_RESULT_VOID(FUNCTION_LOG_OBJECT_FORMAT(compress, lz4CompressToLog, buffer, sizeof(buffer)), "lz4CompressToLog");
        TEST_RESULT_Z(buffer, "{level: 7, first: true, inputSame: true, flushing: true}", "check log");

        Lz4Decompress *decompress = (Lz4Decompress *)ioFilterDriver(lz4DecompressNew(false));

        decompress->inputSame = true;
        decompress->done = true;
        decompress->inputOffset = 999;

        TEST_RESULT_VOID(FUNCTION_LOG_OBJECT_FORMAT(decompress, lz4DecompressToLog, buffer, sizeof(buffer)), "lz4DecompressToLog");
        TEST_RESULT_Z(buffer, "{inputSame: true, inputOffset: 999, frameDone false, done: true}", "check log");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("lz4Compress differential vs direct liblz4 (10000+ inputs)");

        // 10 000 random `(level, raw, input)` triples. liblz4's frame-format encoder is deterministic given fixed prefs +
        // LZ4F_VERSION, so the new FFI path and `legacy_lz4Compress` (direct LZ4F calls with the same prefs) must produce
        // byte-identical frames.
        uint64_t lz4LcgState = UINT64_C(0xACE0FFEEDEADBEEF);
        unsigned int lz4Comparisons = 0;

        for (unsigned int iter = 0; iter < 10000; iter++)
        {
            lz4LcgState = lz4LcgState * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);

            const size_t lz4Len = (size_t)((lz4LcgState >> 32) & 0x3FF) + 1;            // 1..1024 bytes
            // Range matches LZ4_COMPRESS_LEVEL_MIN..MAX (-5..12) → 18 distinct values.
            const int lz4Level = (int)(((lz4LcgState >> 24) & 0xFF) % 18) - 5;
            const bool lz4Raw = ((lz4LcgState >> 16) & 1) == 0;

            Buffer *const lz4Input = bufNew(lz4Len);
            for (size_t i = 0; i < lz4Len; i++)
            {
                lz4LcgState = lz4LcgState * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
                bufPtr(lz4Input)[i] = (uint8_t)(lz4LcgState >> 56);
            }
            bufUsedSet(lz4Input, lz4Len);

            Buffer *const lz4NewOut = testCompress(
                compressFilterP(compressTypeLz4, lz4Level, .raw = lz4Raw), lz4Input, lz4Len, lz4Len * 2 + 256);
            Buffer *const lz4LegacyOut = legacy_lz4Compress(lz4Level, lz4Raw, lz4Input);

            if (!bufEq(lz4NewOut, lz4LegacyOut))
            {
                TEST_ERROR_FMT(
                    THROW_FMT(AssertError, "differential mismatch"),
                    AssertError,
                    "lz4Compress(level=%d, raw=%d, len=%zu) iter=%u newSize=%zu legacySize=%zu", lz4Level, (int)lz4Raw, lz4Len,
                    iter, bufUsed(lz4NewOut), bufUsed(lz4LegacyOut));
            }

            bufFree(lz4Input);
            bufFree(lz4NewOut);
            bufFree(lz4LegacyOut);

            lz4Comparisons++;
        }

        TEST_RESULT_UINT(lz4Comparisons, 10000, "10k differential lz4Compress inputs all byte-identical");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("lz4Decompress differential vs direct liblz4 (10000+ inputs)");

        // 10 000 random plaintexts. Compress each through the (already-validated) Phase 18 path then decompress through both the
        // new FFI path and `legacy_lz4Decompress` (direct LZ4F calls with the same prefs). Both paths must recover the original
        // plaintext byte-for-byte AND agree with each other.
        uint64_t lz4DcLcg = UINT64_C(0xBADC0FFEE0FF1CE5);
        unsigned int lz4DcComparisons = 0;

        for (unsigned int iter = 0; iter < 10000; iter++)
        {
            lz4DcLcg = lz4DcLcg * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);

            const size_t lz4DcLen = (size_t)((lz4DcLcg >> 32) & 0x3FF) + 1;
            const int lz4DcLevel = (int)(((lz4DcLcg >> 24) & 0xFF) % 18) - 5;
            const bool lz4DcRaw = ((lz4DcLcg >> 16) & 1) == 0;

            Buffer *const lz4DcPlaintext = bufNew(lz4DcLen);
            for (size_t i = 0; i < lz4DcLen; i++)
            {
                lz4DcLcg = lz4DcLcg * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
                bufPtr(lz4DcPlaintext)[i] = (uint8_t)(lz4DcLcg >> 56);
            }
            bufUsedSet(lz4DcPlaintext, lz4DcLen);

            Buffer *const lz4DcCompressed = testCompress(
                compressFilterP(compressTypeLz4, lz4DcLevel, .raw = lz4DcRaw), lz4DcPlaintext, lz4DcLen, lz4DcLen * 2 + 256);

            Buffer *const lz4DcNewOut = testDecompress(
                decompressFilterP(compressTypeLz4, .raw = lz4DcRaw), lz4DcCompressed, lz4DcLen, lz4DcLen + 1);
            Buffer *const lz4DcLegacyOut = legacy_lz4Decompress(lz4DcCompressed);

            if (!bufEq(lz4DcNewOut, lz4DcPlaintext) || !bufEq(lz4DcLegacyOut, lz4DcPlaintext) || !bufEq(lz4DcNewOut, lz4DcLegacyOut))
            {
                TEST_ERROR_FMT(
                    THROW_FMT(AssertError, "differential mismatch"),
                    AssertError,
                    "lz4Decompress(level=%d, raw=%d, len=%zu) iter=%u newSize=%zu legacySize=%zu plaintextSize=%zu", lz4DcLevel,
                    (int)lz4DcRaw, lz4DcLen, iter, bufUsed(lz4DcNewOut), bufUsed(lz4DcLegacyOut), bufUsed(lz4DcPlaintext));
            }

            bufFree(lz4DcPlaintext);
            bufFree(lz4DcCompressed);
            bufFree(lz4DcNewOut);
            bufFree(lz4DcLegacyOut);

            lz4DcComparisons++;
        }

        TEST_RESULT_UINT(lz4DcComparisons, 10000, "10k differential lz4Decompress inputs all byte-identical");
    }

    // *****************************************************************************************************************************
    if (testBegin("zst"))
    {
#ifdef HAVE_LIBZST
        // Run standard test suite
        testSuite(compressTypeZst, "zstd -dc", 0);

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("zstError()");

        TEST_RESULT_UINT(zstError(0), 0, "check success");
        TEST_ERROR(zstError((size_t)-12), FormatError, "zst error: [-12] Version not supported");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("zstDecompressToLog() and zstCompressToLog()");

        char buffer[STACK_TRACE_PARAM_MAX];

        ZstCompress *compress = (ZstCompress *)ioFilterDriver(zstCompressNew(14, false));

        compress->inputSame = true;
        compress->inputOffset = 49;
        compress->flushing = true;

        TEST_RESULT_VOID(FUNCTION_LOG_OBJECT_FORMAT(compress, zstCompressToLog, buffer, sizeof(buffer)), "zstCompressToLog");
        TEST_RESULT_Z(buffer, "{level: 14, inputSame: true, inputOffset: 49, flushing: true}", "check log");

        ZstDecompress *decompress = (ZstDecompress *)ioFilterDriver(zstDecompressNew(false));

        decompress->inputSame = true;
        decompress->done = true;
        decompress->inputOffset = 999;

        TEST_RESULT_VOID(FUNCTION_LOG_OBJECT_FORMAT(decompress, zstDecompressToLog, buffer, sizeof(buffer)), "zstDecompressToLog");
        TEST_RESULT_Z(buffer, "{inputSame: true, inputOffset: 999, frameDone false, done: true}", "check log");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("zstCompress differential vs direct libzstd (10000+ inputs)");

        // 10 000 random `(level, plaintext)` pairs. libzstd is deterministic given fixed level + ZSTD_initCStream defaults, so
        // the new FFI path and `legacy_zstCompress` (direct libzstd calls with the same level) must produce byte-identical
        // frames.
        uint64_t zstLcgState = UINT64_C(0xC0FFEE0005A5A5A5);
        unsigned int zstComparisons = 0;

        for (unsigned int iter = 0; iter < 10000; iter++)
        {
            zstLcgState = zstLcgState * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);

            const size_t zstLen = (size_t)((zstLcgState >> 32) & 0x3FF) + 1;
            // ZST_COMPRESS_LEVEL_MIN..MAX is -7..22 → 30 values.
            const int zstLevel = (int)(((zstLcgState >> 24) & 0xFF) % 30) - 7;

            Buffer *const zstInput = bufNew(zstLen);
            for (size_t i = 0; i < zstLen; i++)
            {
                zstLcgState = zstLcgState * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
                bufPtr(zstInput)[i] = (uint8_t)(zstLcgState >> 56);
            }
            bufUsedSet(zstInput, zstLen);

            Buffer *const zstNewOut = testCompress(
                compressFilterP(compressTypeZst, zstLevel), zstInput, zstLen, zstLen * 2 + 4096);
            Buffer *const zstLegacyOut = legacy_zstCompress(zstLevel, zstInput);

            if (!bufEq(zstNewOut, zstLegacyOut))
            {
                TEST_ERROR_FMT(
                    THROW_FMT(AssertError, "differential mismatch"),
                    AssertError,
                    "zstCompress(level=%d, len=%zu) iter=%u newSize=%zu legacySize=%zu", zstLevel, zstLen, iter,
                    bufUsed(zstNewOut), bufUsed(zstLegacyOut));
            }

            bufFree(zstInput);
            bufFree(zstNewOut);
            bufFree(zstLegacyOut);

            zstComparisons++;
        }

        TEST_RESULT_UINT(zstComparisons, 10000, "10k differential zstCompress inputs all byte-identical");
#else
        TEST_ERROR(compressTypePresent(compressTypeZst), OptionInvalidValueError, "pgBackRust not built with zst support");
#endif // HAVE_LIBZST
    }

    // *****************************************************************************************************************************
    if (testBegin("compressParamList() / decompressParamList() differential"))
    {
        // 12 000 deterministic (level, raw) combinations: 1 000 inputs × 12 (level ∈ {-3..9, 0 included}, raw ∈ {false,true}).
        // For each, build the Pack via the new Rust path (`compressParamList`) and via a `legacy_*` helper that calls the C
        // `pckWrite*` chain directly. The byte buffers must match exactly — Pack is a `Buffer *` cast, so a bytewise compare on
        // `pckToBuf` is the strict differential.
        unsigned int comparisons = 0;
        uint64_t state = UINT64_C(0xFEEDF00DBEEFCAFE);

        for (unsigned int iter = 0; iter < 1000; iter++)
        {
            for (int level = -3; level <= 9; level++)
            {
                for (unsigned int rawIdx = 0; rawIdx < 2; rawIdx++)
                {
                    state = state * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
                    const bool raw = (rawIdx == 0);

                    Pack *const rustPack = compressParamList(level, raw);
                    Pack *const legacyPack = legacy_compressParamList(level, raw);

                    if (!bufEq(pckToBuf(rustPack), pckToBuf(legacyPack)))
                    {
                        TEST_ERROR_FMT(
                            THROW_FMT(AssertError, "differential mismatch"),
                            AssertError,
                            "compressParamList(level=%d, raw=%d) iter=%u", level, (int)raw, iter);
                    }

                    comparisons++;
                }
            }
        }

        for (unsigned int rawIdx = 0; rawIdx < 2; rawIdx++)
        {
            const bool raw = (rawIdx == 0);
            Pack *const rustPack = decompressParamList(raw);
            Pack *const legacyPack = legacy_decompressParamList(raw);

            if (!bufEq(pckToBuf(rustPack), pckToBuf(legacyPack)))
            {
                TEST_ERROR_FMT(
                    THROW_FMT(AssertError, "differential mismatch"),
                    AssertError,
                    "decompressParamList(raw=%d)", (int)raw);
            }

            comparisons++;
        }

        TEST_RESULT_UINT(comparisons, 1000 * 13 * 2 + 2, "all C/Rust differential comparisons agreed");
    }

    // Test everything in the helper that is not tested in the individual compression type tests
    // *****************************************************************************************************************************
    if (testBegin("helper"))
    {
        TEST_TITLE("compressTypeEnum()");

        TEST_RESULT_UINT(compressTypeEnum(strIdFromZ("none")), compressTypeNone, "none enum");
        TEST_RESULT_UINT(compressTypeEnum(strIdFromZ("gz")), compressTypeGz, "gz enum");
        TEST_ERROR(compressTypeEnum(strIdFromZ(BOGUS_STR)), AssertError, "invalid compression type 'BOGUS'");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("compressTypeStr()");

        TEST_RESULT_STR_Z(compressTypeStr(compressTypeGz), "gz", "gz str");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("compressTypePresent()");

        TEST_RESULT_VOID(compressTypePresent(compressTypeNone), "type none always present");
        TEST_ERROR(compressTypePresent(compressTypeXz), OptionInvalidValueError, "pgBackRust not built with xz support");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("compressTypeFromName()");

        TEST_RESULT_UINT(compressTypeFromName(STRDEF("file")), compressTypeNone, "type from name");
        TEST_RESULT_UINT(compressTypeFromName(STRDEF("file.gz")), compressTypeGz, "type from name");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("compressFilterPack()");

        TEST_RESULT_PTR(compressFilterPack(STRID5("bogus", 0x13a9de20), NULL), NULL, "no filter match");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("compressExtStr()");

        TEST_RESULT_STR_Z(compressExtStr(compressTypeNone), "", "one ext");
        TEST_RESULT_STR_Z(compressExtStr(compressTypeGz), ".gz", "gz ext");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("compressExtCat()");

        String *file = strCatZ(strNew(), "file");
        TEST_RESULT_VOID(compressExtCat(file, compressTypeGz), "cat gz ext");
        TEST_RESULT_STR_Z(file, "file.gz", "    check gz ext");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("compressExtStrip()");

        TEST_ERROR(compressExtStrip(STRDEF("file"), compressTypeGz), FormatError, "'file' must have '.gz' extension");
        TEST_RESULT_STR_Z(compressExtStrip(STRDEF("file"), compressTypeNone), "file", "nothing to strip");
        TEST_RESULT_STR_Z(compressExtStrip(STRDEF("file.gz"), compressTypeGz), "file", "strip gz");
    }

    FUNCTION_HARNESS_RETURN_VOID();
}
