/***********************************************************************************************************************************
Cryptographic Hash

Thin C wrappers over the Rust implementation in `crates/pgbr-crypto::hash`. The actual MD5 / SHA1 / SHA256 / HMAC routines live in
libpgbr_ffi.a; this file keeps the public API in `src/common/crypto/hash.h` byte-identical to the legacy version, including the
streaming `IoFilter` integration. The opaque Rust hash state stands in for the legacy `EVP_MD_CTX` + bundled MD5 union — the C
struct only needs to remember the algorithm (for size lookup and re-finalize idempotency) and cache the binary digest.
***********************************************************************************************************************************/
#include <build.h>

#include "common/crypto/common.h"
#include "common/crypto/hash.h"
#include "common/debug.h"
#include "common/io/filter/filter.h"
#include "common/log.h"
#include "common/type/object.h"
#include "common/type/pack.h"
#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Hashes for zero-length files (i.e., seed value)
***********************************************************************************************************************************/
BUFFER_EXTERN(
    HASH_TYPE_SHA1_ZERO_BUF, 0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf,
    0xd8, 0x07, 0x09);
BUFFER_EXTERN(
    HASH_TYPE_SHA256_ZERO_BUF, 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27,
    0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55);

/***********************************************************************************************************************************
Object type
***********************************************************************************************************************************/
typedef struct CryptoHash
{
    int32_t typeCode;                                               // Numeric pgbr_crypto::hash::HashType discriminant
    void *state;                                                    // Opaque Rust handle from pgbr_crypto_hash_state_new
    Buffer *hash;                                                   // Cached binary digest after first finalize
} CryptoHash;

/***********************************************************************************************************************************
Macros for function logging
***********************************************************************************************************************************/
#define FUNCTION_LOG_CRYPTO_HASH_TYPE                                                                                              \
    CryptoHash *
#define FUNCTION_LOG_CRYPTO_HASH_FORMAT(value, buffer, bufferSize)                                                                 \
    objNameToLog(value, "CryptoHash", buffer, bufferSize)

/***********************************************************************************************************************************
Map a HashType StringId to the numeric code understood by the FFI layer.
***********************************************************************************************************************************/
static int32_t
cryptoHashTypeCode(const HashType type)
{
    switch (type)
    {
        case hashTypeMd5:
            return 0;

        case hashTypeSha1:
            return 1;

        case hashTypeSha256:
            return 2;

        default:
        {
            char typeZ[STRID_MAX + 1];
            strIdToZ(type, typeZ);
            THROW_FMT(AssertError, "unable to load hash '%s'", typeZ);
        }
    }
}

/***********************************************************************************************************************************
Free hash context
***********************************************************************************************************************************/
static void
cryptoHashFreeResource(THIS_VOID)
{
    THIS(CryptoHash);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(CRYPTO_HASH, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    pgbr_crypto_hash_state_free(this->state);
    this->state = NULL;

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Add message data to the hash from a Buffer
***********************************************************************************************************************************/
static void
cryptoHashProcess(THIS_VOID, const Buffer *const message)
{
    THIS(CryptoHash);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(CRYPTO_HASH, this);
        FUNCTION_LOG_PARAM(BUFFER, message);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(this->hash == NULL);
    ASSERT(message != NULL);

    if (pgbr_crypto_hash_state_update(this->state, bufPtrConst(message), bufUsed(message)) != 0)
        THROW_FMT(CryptoError, "unable to process message hash: %s", pgbr_last_error_msg());

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Get binary representation of the hash
***********************************************************************************************************************************/
static const Buffer *
cryptoHash(CryptoHash *const this)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(CRYPTO_HASH, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    if (this->hash == NULL)
    {
        MEM_CONTEXT_OBJ_BEGIN(this)
        {
            const size_t hashSize = pgbr_crypto_hash_size(this->typeCode);
            ASSERT(hashSize > 0);

            this->hash = bufNew(hashSize);

            const intptr_t written = pgbr_crypto_hash_state_finalize_into(this->state, bufPtr(this->hash), hashSize);

            if (written < 0 || (size_t)written != hashSize)
                THROW_FMT(CryptoError, "unable to finalize message hash: %s", pgbr_last_error_msg());

            bufUsedSet(this->hash, hashSize);
        }
        MEM_CONTEXT_OBJ_END();
    }

    FUNCTION_LOG_RETURN(BUFFER, this->hash);
}

/***********************************************************************************************************************************
Get string representation of the hash as a filter result
***********************************************************************************************************************************/
static Pack *
cryptoHashResult(THIS_VOID)
{
    THIS(CryptoHash);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(CRYPTO_HASH, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    Pack *result = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        PackWrite *const packWrite = pckWriteNewP();

        pckWriteBinP(packWrite, cryptoHash(this));
        pckWriteEndP(packWrite);

        result = pckMove(pckWriteResult(packWrite), memContextPrior());
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_LOG_RETURN(PACK, result);
}

/**********************************************************************************************************************************/
FN_EXTERN IoFilter *
cryptoHashNew(const HashType type)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STRING_ID, type);
    FUNCTION_LOG_END();

    ASSERT(type != 0);

    // Init crypto subsystem
    cryptoInit();

    // Resolve the algorithm code up-front so an unsupported `type` throws AssertError before any allocation happens, matching the
    // legacy "unable to load hash 'xxx'" behaviour.
    const int32_t typeCode = cryptoHashTypeCode(type);

    OBJ_NEW_BEGIN(CryptoHash, .childQty = MEM_CONTEXT_QTY_MAX, .callbackQty = 1)
    {
        *this = (CryptoHash){.typeCode = typeCode};

        this->state = pgbr_crypto_hash_state_new(typeCode);

        if (this->state == NULL)
            THROW_FMT(CryptoError, "unable to create hash context: %s", pgbr_last_error_msg());

        // Set free callback to ensure hash state is freed
        memContextCallbackSet(objMemContext(this), cryptoHashFreeResource, this);
    }
    OBJ_NEW_END();

    // Create param list
    Pack *paramList;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        PackWrite *const packWrite = pckWriteNewP();

        pckWriteStrIdP(packWrite, type);
        pckWriteEndP(packWrite);

        paramList = pckMove(pckWriteResult(packWrite), memContextPrior());
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_LOG_RETURN(
        IO_FILTER, ioFilterNewP(CRYPTO_HASH_FILTER_TYPE, this, paramList, .in = cryptoHashProcess, .result = cryptoHashResult));
}

FN_EXTERN IoFilter *
cryptoHashNewPack(const Pack *const paramList)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(PACK, paramList);
    FUNCTION_TEST_END();

    IoFilter *result = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        result = ioFilterMove(cryptoHashNew(pckReadStrIdP(pckReadNew(paramList))), memContextPrior());
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_TEST_RETURN(IO_FILTER, result);
}

/**********************************************************************************************************************************/
FN_EXTERN Buffer *
cryptoHashOne(const HashType type, const Buffer *const message)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STRING_ID, type);
        FUNCTION_LOG_PARAM(BUFFER, message);
    FUNCTION_LOG_END();

    ASSERT(type != 0);
    ASSERT(message != NULL);

    cryptoInit();

    const int32_t typeCode = cryptoHashTypeCode(type);
    const size_t hashSize = pgbr_crypto_hash_size(typeCode);
    ASSERT(hashSize > 0);

    Buffer *const result = bufNew(hashSize);

    const intptr_t written = pgbr_crypto_hash_one_into(typeCode, bufPtrConst(message), bufUsed(message), bufPtr(result), hashSize);

    if (written < 0 || (size_t)written != hashSize)
        THROW_FMT(CryptoError, "unable to compute hash: %s", pgbr_last_error_msg());

    bufUsedSet(result, hashSize);

    FUNCTION_LOG_RETURN(BUFFER, result);
}

/**********************************************************************************************************************************/
FN_EXTERN Buffer *
cryptoHmacOne(const HashType type, const Buffer *const key, const Buffer *const message)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STRING_ID, type);
        FUNCTION_LOG_PARAM(BUFFER, key);
        FUNCTION_LOG_PARAM(BUFFER, message);
    FUNCTION_LOG_END();

    ASSERT(type != 0);
    ASSERT(key != NULL);
    ASSERT(message != NULL);

    cryptoInit();

    const int32_t typeCode = cryptoHashTypeCode(type);
    const size_t hashSize = pgbr_crypto_hash_size(typeCode);
    ASSERT(hashSize > 0);

    Buffer *const result = bufNew(hashSize);

    const intptr_t written = pgbr_crypto_hmac_one_into(
        typeCode, bufPtrConst(key), bufUsed(key), bufPtrConst(message), bufUsed(message), bufPtr(result), hashSize);

    if (written < 0 || (size_t)written != hashSize)
        THROW_FMT(CryptoError, "unable to compute hmac: %s", pgbr_last_error_msg());

    bufUsedSet(result, hashSize);

    FUNCTION_LOG_RETURN(BUFFER, result);
}
