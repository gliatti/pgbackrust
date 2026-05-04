/***********************************************************************************************************************************
Block Cipher

The IoFilter integration, header / salt / `Salted__` magic state machine, and buffer management stay on the C side because they
are tightly coupled to the IoFilter wrapper, which is not migrated yet (separate phase). The libcrypto-direct calls
(EVP_get_cipherbyname, EVP_get_digestbyname, EVP_BytesToKey, EVP_CipherInit_ex, EVP_CipherUpdate, EVP_CipherFinal) are replaced by
thin wrappers over the Rust pgbr-crypto::cipher exports — the algorithm name -> code mapping, key derivation, streaming update,
and final flush all flow through libpgbr_ffi.a.
***********************************************************************************************************************************/
#include <build.h>

#include <string.h>

#include "common/crypto/cipherBlock.h"
#include "common/crypto/common.h"
#include "common/debug.h"
#include "common/io/filter/filter.h"
#include "common/log.h"
#include "common/type/object.h"
#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Header constants and sizes
***********************************************************************************************************************************/
// Magic constant for salted encrypt. Only salted encrypt is done here, but this constant is required for compatibility with the
// openssl command-line tool.
#define CIPHER_BLOCK_MAGIC                                          "Salted__"
#define CIPHER_BLOCK_MAGIC_SIZE                                     (sizeof(CIPHER_BLOCK_MAGIC) - 1)

// PKCS5 salt size — replicated from the legacy `openssl/evp.h` constant so the cipherBlock module no longer needs to include
// libcrypto headers.
#define PKCS5_SALT_LEN                                              8

// Upper bound on cipher block size — replicated from `openssl/evp.h` (EVP_MAX_BLOCK_LENGTH = 32). Used for buffer pre-sizing so
// the legacy `cipherBlockProcessSize` upper bound stays unchanged. Tighter per-cipher sizes are still queried via FFI when the
// caller knows which cipher is in play.
#define CIPHER_BLOCK_MAX_BLOCK_LENGTH                               32

// Total length of cipher header
#define CIPHER_BLOCK_HEADER_SIZE                                    (CIPHER_BLOCK_MAGIC_SIZE + PKCS5_SALT_LEN)

// Numeric pgbr_crypto::cipher::CipherType discriminant — zero is the only supported value (AES-256-CBC).
#define CIPHER_BLOCK_CIPHER_AES256CBC                               0

// Numeric pgbr_crypto::cipher::Mode discriminants matching the `Mode` enum.
#define CIPHER_BLOCK_MODE_ENCRYPT                                   0
#define CIPHER_BLOCK_MODE_DECRYPT                                   1

/***********************************************************************************************************************************
Object type
***********************************************************************************************************************************/
typedef struct CipherBlock
{
    CipherMode mode;                                                // Mode encrypt/decrypt
    bool raw;                                                       // Omit header magic to save space
    bool saltDone;                                                  // Has the salt been read/generated?
    bool processDone;                                               // Has any data been processed?
    const Buffer *pass;                                             // Passphrase used to generate encryption key
    size_t headerSize;                                              // Size of header read during decrypt
    uint8_t header[CIPHER_BLOCK_HEADER_SIZE];                       // Buffer to hold partial header during decrypt
    int32_t cipherCode;                                             // pgbr_crypto::cipher::CipherType discriminant
    int32_t digestCode;                                             // pgbr_crypto::hash::HashType discriminant for key derivation
    void *cipherState;                                              // Opaque pgbr_crypto::cipher::State* (set after derive)

    Buffer *buffer;                                                 // Internal buffer in case destination buffer isn't large enough
    bool inputSame;                                                 // Is the same input required on next process call?
    bool done;                                                      // Is processing done?
} CipherBlock;

/***********************************************************************************************************************************
Macros for function logging
***********************************************************************************************************************************/
static void
cipherBlockToLog(const CipherBlock *const this, StringStatic *const debugLog)
{
    strStcFmt(debugLog, "{inputSame: %s, done: %s}", cvtBoolToConstZ(this->inputSame), cvtBoolToConstZ(this->done));
}

#define FUNCTION_LOG_CIPHER_BLOCK_TYPE                                                                                             \
    CipherBlock *
#define FUNCTION_LOG_CIPHER_BLOCK_FORMAT(value, buffer, bufferSize)                                                                \
    FUNCTION_LOG_OBJECT_FORMAT(value, cipherBlockToLog, buffer, bufferSize)

/***********************************************************************************************************************************
Map a CipherType StringId to the numeric code understood by the FFI layer. cipherTypeNone is rejected here because the public
header (`cipherBlockFilterGroupAdd`) handles "no encryption" before reaching this module.
***********************************************************************************************************************************/
static int32_t
cipherBlockCipherCode(const CipherType type)
{
    switch (type)
    {
        case cipherTypeAes256Cbc:
            return CIPHER_BLOCK_CIPHER_AES256CBC;

        default:
        {
            char *const typeZ = zNewStrId(type);
            String *const message = strNewFmt("unable to load cipher '%s'", typeZ);
            zFree(typeZ);
            THROW(AssertError, strZ(message));
        }
    }
}

/***********************************************************************************************************************************
Map a digest name (from CipherBlockNewParam.digest) to the numeric HashType code. Defaults to SHA1 when unset, matching the
legacy code's `EVP_sha1()` fallback.
***********************************************************************************************************************************/
static int32_t
cipherBlockDigestCode(const String *const digest)
{
    if (digest == NULL || strEqZ(digest, "sha1"))
        return 1;

    if (strEqZ(digest, "sha256"))
        return 2;

    if (strEqZ(digest, "md5"))
        return 0;

    THROW_FMT(AssertError, "unable to load digest '%s'", strZ(digest));
}

/***********************************************************************************************************************************
Free cipher state
***********************************************************************************************************************************/
static void
cipherBlockFreeResource(THIS_VOID)
{
    THIS(CipherBlock);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(CIPHER_BLOCK, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    pgbr_crypto_cipher_state_free(this->cipherState);
    this->cipherState = NULL;

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Determine how large the destination buffer should be
***********************************************************************************************************************************/
static size_t
cipherBlockProcessSize(const CipherBlock *const this, const size_t sourceSize)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(CIPHER_BLOCK, this);
        FUNCTION_LOG_PARAM(SIZE, sourceSize);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    // Destination size is source size plus one extra block (use the legacy EVP_MAX_BLOCK_LENGTH upper bound to keep the public
    // sizing contract identical across the migration).
    size_t destinationSize = sourceSize + CIPHER_BLOCK_MAX_BLOCK_LENGTH;

    // On encrypt the header size must be included before the first block
    if (this->mode == cipherModeEncrypt && !this->saltDone)
        destinationSize += CIPHER_BLOCK_MAGIC_SIZE + PKCS5_SALT_LEN;

    FUNCTION_LOG_RETURN(SIZE, destinationSize);
}

/***********************************************************************************************************************************
Encrypt/decrypt data
***********************************************************************************************************************************/
static size_t
cipherBlockProcessBlock(CipherBlock *const this, const uint8_t *source, size_t sourceSize, uint8_t *destination)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(CIPHER_BLOCK, this);
        FUNCTION_LOG_PARAM_P(BYTEDATA, source);
        FUNCTION_LOG_PARAM(SIZE, sourceSize);
        FUNCTION_LOG_PARAM_P(BYTEDATA, destination);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(source != NULL || sourceSize == 0);
    ASSERT(destination != NULL);

    // Actual destination size
    size_t destinationSize = 0;

    // If the salt has not been generated/read yet
    if (!this->saltDone)
    {
        const uint8_t *salt = NULL;

        // On encrypt the salt is generated
        if (this->mode == cipherModeEncrypt)
        {
            // Add magic to the destination buffer so openssl knows the file is salted
            if (!this->raw)
            {
                memcpy(destination, CIPHER_BLOCK_MAGIC, CIPHER_BLOCK_MAGIC_SIZE);
                destination += CIPHER_BLOCK_MAGIC_SIZE;
                destinationSize += CIPHER_BLOCK_MAGIC_SIZE;
            }

            // Add salt to the destination buffer
            cryptoRandomBytes(destination, PKCS5_SALT_LEN);
            salt = destination;
            destination += PKCS5_SALT_LEN;
            destinationSize += PKCS5_SALT_LEN;
        }
        // On decrypt the salt is read from the header
        else if (sourceSize > 0)
        {
            // Check if the entire header has been read
            const size_t headerExpected = this->raw ? PKCS5_SALT_LEN : CIPHER_BLOCK_HEADER_SIZE;

            if (this->headerSize + sourceSize >= headerExpected)
            {
                // Copy header (or remains of header) from source into the header buffer
                memcpy(this->header + this->headerSize, source, headerExpected - this->headerSize);
                salt = this->header + (this->raw ? 0 : CIPHER_BLOCK_MAGIC_SIZE);

                // Advance source and source size by the number of bytes read
                source += headerExpected - this->headerSize;
                sourceSize -= headerExpected - this->headerSize;

                // The first bytes of the file to decrypt should be equal to the magic. If not then this is not an encrypted file,
                // or at least not in a format we recognize.
                if (!this->raw && memcmp(this->header, CIPHER_BLOCK_MAGIC, CIPHER_BLOCK_MAGIC_SIZE) != 0)
                    THROW(CryptoError, "cipher header invalid");
            }
            // Else copy what was provided into the header buffer and return 0
            else
            {
                memcpy(this->header + this->headerSize, source, sourceSize);
                this->headerSize += sourceSize;

                // Indicate that there is nothing left to process
                sourceSize = 0;
            }
        }

        // If salt generation/read is done, derive the key + IV and create the cipher state.
        if (salt)
        {
            const size_t keyLen = pgbr_crypto_cipher_key_len(this->cipherCode);
            const size_t ivLen = pgbr_crypto_cipher_iv_len(this->cipherCode);
            uint8_t key[64];
            uint8_t initVector[64];

            ASSERT(keyLen > 0 && keyLen <= sizeof(key));
            ASSERT(ivLen > 0 && ivLen <= sizeof(initVector));

            if (pgbr_crypto_cipher_derive_key_iv(
                    this->cipherCode, this->digestCode, salt, PKCS5_SALT_LEN, bufPtrConst(this->pass), bufSize(this->pass),
                    key, sizeof(key), initVector, sizeof(initVector)) != 0)
            {
                THROW_FMT(CryptoError, "unable to derive cipher key: %s", pgbr_last_error_msg());
            }

            this->cipherState = pgbr_crypto_cipher_state_new(
                this->cipherCode, this->mode == cipherModeEncrypt ? CIPHER_BLOCK_MODE_ENCRYPT : CIPHER_BLOCK_MODE_DECRYPT,
                key, keyLen, initVector, ivLen);

            if (this->cipherState == NULL)
                THROW_FMT(CryptoError, "unable to initialize cipher: %s", pgbr_last_error_msg());

            // Set free callback to ensure cipher state is freed
            memContextCallbackSet(objMemContext(this), cipherBlockFreeResource, this);

            this->saltDone = true;
        }
    }

    // Recheck that source size > 0 as the bytes may have been consumed reading the header
    if (sourceSize > 0)
    {
        const intptr_t written = pgbr_crypto_cipher_state_update(
            this->cipherState, source, sourceSize, destination, sourceSize + CIPHER_BLOCK_MAX_BLOCK_LENGTH);

        if (written < 0)
        {
            pgbr_last_error_clear();
            THROW(CryptoError, "unable to process cipher");
        }

        destinationSize += (size_t)written;

        // Note that data has been processed so flush is valid
        this->processDone = true;
    }

    // Return actual destination size
    FUNCTION_LOG_RETURN(SIZE, destinationSize);
}

/***********************************************************************************************************************************
Flush the remaining data
***********************************************************************************************************************************/
static size_t
cipherBlockFlush(CipherBlock *const this, Buffer *const destination)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(CIPHER_BLOCK, this);
        FUNCTION_LOG_PARAM(BUFFER, destination);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(destination != NULL);

    // If no header was processed then error
    if (!this->saltDone)
        THROW(CryptoError, "cipher header missing");

    // Only flush remaining data if some data was processed
    const intptr_t written = pgbr_crypto_cipher_state_finalize(
        this->cipherState, bufRemainsPtr(destination), bufRemains(destination));

    if (written < 0)
    {
        pgbr_last_error_clear();
        THROW(CryptoError, "unable to flush");
    }

    // Return actual destination size
    FUNCTION_LOG_RETURN(SIZE, (size_t)written);
}

/***********************************************************************************************************************************
Process function used by C filter
***********************************************************************************************************************************/
static void
cipherBlockProcess(THIS_VOID, const Buffer *const source, Buffer *const destination)
{
    THIS(CipherBlock);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(CIPHER_BLOCK, this);
        FUNCTION_LOG_PARAM(BUFFER, source);
        FUNCTION_LOG_PARAM(BUFFER, destination);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(destination != NULL);
    ASSERT(bufRemains(destination) > 0);

    // Copy already buffered bytes
    if (this->buffer != NULL && !bufEmpty(this->buffer))
    {
        if (bufRemains(destination) >= bufUsed(this->buffer))
        {
            bufCat(destination, this->buffer);
            bufUsedZero(this->buffer);

            this->inputSame = false;
        }
        else
        {
            const size_t catSize = bufRemains(destination);
            bufCatSub(destination, this->buffer, 0, catSize);

            memmove(bufPtr(this->buffer), bufPtr(this->buffer) + catSize, bufUsed(this->buffer) - catSize);
            bufUsedSet(this->buffer, bufUsed(this->buffer) - catSize);

            this->inputSame = true;
        }
    }
    else
    {
        ASSERT(this->buffer == NULL || bufEmpty(this->buffer));

        // Determine how much space is required in the output buffer
        Buffer *outputActual = destination;

        const size_t destinationSize = cipherBlockProcessSize(this, source == NULL ? 0 : bufUsed(source));

        if (destinationSize > bufRemains(destination))
        {
            // Allocate the buffer if needed
            MEM_CONTEXT_OBJ_BEGIN(this)
            {
                if (this->buffer == NULL)
                {
                    this->buffer = bufNew(destinationSize);
                }
                // Resize buffer if needed
                else
                    bufResize(this->buffer, destinationSize);
            }
            MEM_CONTEXT_OBJ_END();

            outputActual = this->buffer;
        }

        // Encrypt/decrypt bytes
        size_t destinationSizeActual;

        if (source == NULL)
        {
            // If salt was not generated it means that process() was never called with any data. It's OK to encrypt a zero byte file
            // but we need to call process to generate the header.
            if (!this->saltDone)
            {
                destinationSizeActual = cipherBlockProcessBlock(this, NULL, 0, bufRemainsPtr(outputActual));
                bufUsedInc(outputActual, destinationSizeActual);
            }

            destinationSizeActual = cipherBlockFlush(this, outputActual);
            this->done = true;
        }
        else
        {
            destinationSizeActual = cipherBlockProcessBlock(
                this, bufPtrConst(source), bufUsed(source), bufRemainsPtr(outputActual));
        }

        bufUsedInc(outputActual, destinationSizeActual);

        // Copy from buffer to destination if needed
        if (this->buffer != NULL && !bufEmpty(this->buffer))
            cipherBlockProcess(this, source, destination);
    }

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Is cipher done?
***********************************************************************************************************************************/
static bool
cipherBlockDone(const THIS_VOID)
{
    THIS(const CipherBlock);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(CIPHER_BLOCK, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->done && !this->inputSame);
}

/***********************************************************************************************************************************
Should the same input be provided again?
***********************************************************************************************************************************/
static bool
cipherBlockInputSame(const THIS_VOID)
{
    THIS(const CipherBlock);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(CIPHER_BLOCK, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->inputSame);
}

/**********************************************************************************************************************************/
FN_EXTERN IoFilter *
cipherBlockNew(const CipherMode mode, const CipherType cipherType, const Buffer *const pass, const CipherBlockNewParam param)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STRING_ID, mode);
        FUNCTION_LOG_PARAM(STRING_ID, cipherType);
        FUNCTION_TEST_PARAM(BUFFER, pass);                          // Use FUNCTION_TEST so passphrase is not logged
        FUNCTION_LOG_PARAM(STRING, param.digest);
        FUNCTION_LOG_PARAM(BOOL, param.raw);
    FUNCTION_LOG_END();

    ASSERT(pass != NULL);
    ASSERT(!bufEmpty(pass));

    // Init crypto subsystem
    cryptoInit();

    // Resolve cipher and digest codes up-front so an unsupported request raises AssertError before any allocation happens, just
    // like the legacy `EVP_get_*byname` lookups did.
    const int32_t cipherCode = cipherBlockCipherCode(cipherType);
    const int32_t digestCode = cipherBlockDigestCode(param.digest);

    OBJ_NEW_BEGIN(CipherBlock, .childQty = MEM_CONTEXT_QTY_MAX, .callbackQty = 1)
    {
        *this = (CipherBlock)
        {
            .mode = mode,
            .raw = param.raw,
            .cipherCode = cipherCode,
            .digestCode = digestCode,
            .pass = bufDup(pass),
        };
    }
    OBJ_NEW_END();

    // Create param list
    Pack *paramList;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        PackWrite *const packWrite = pckWriteNewP();

        pckWriteU64P(packWrite, mode);
        pckWriteU64P(packWrite, cipherType);
        pckWriteBinP(packWrite, pass);
        pckWriteStrP(packWrite, param.digest);
        pckWriteBoolP(packWrite, param.raw);
        pckWriteEndP(packWrite);

        paramList = pckMove(pckWriteResult(packWrite), memContextPrior());
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_LOG_RETURN(
        IO_FILTER,
        ioFilterNewP(
            CIPHER_BLOCK_FILTER_TYPE, this, paramList, .done = cipherBlockDone, .inOut = cipherBlockProcess,
            .inputSame = cipherBlockInputSame));
}

FN_EXTERN IoFilter *
cipherBlockNewPack(const Pack *const paramList)
{
    IoFilter *result = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        PackRead *const paramListPack = pckReadNew(paramList);
        const CipherMode cipherMode = (CipherMode)pckReadU64P(paramListPack);
        const CipherType cipherType = (CipherType)pckReadU64P(paramListPack);
        const Buffer *const pass = pckReadBinP(paramListPack);
        const String *const digest = pckReadStrP(paramListPack);
        const bool raw = pckReadBoolP(paramListPack);

        result = ioFilterMove(cipherBlockNewP(cipherMode, cipherType, pass, .digest = digest, .raw = raw), memContextPrior());
    }
    MEM_CONTEXT_TEMP_END();

    return result;
}

/**********************************************************************************************************************************/
FN_EXTERN IoFilterGroup *
cipherBlockFilterGroupAdd(IoFilterGroup *const filterGroup, const CipherType type, const CipherMode mode, const String *const pass)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(IO_FILTER_GROUP, filterGroup);
        FUNCTION_LOG_PARAM(STRING_ID, type);
        FUNCTION_LOG_PARAM(STRING_ID, mode);
        FUNCTION_TEST_PARAM(STRING, pass);                          // Use FUNCTION_TEST so passphrase is not logged
    FUNCTION_LOG_END();

    ASSERT(filterGroup != NULL);
    ASSERT((type == cipherTypeNone && pass == NULL) || (type != cipherTypeNone && pass != NULL));

    if (type != cipherTypeNone)
        ioFilterGroupAdd(filterGroup, cipherBlockNewP(mode, type, BUFSTR(pass)));

    FUNCTION_LOG_RETURN(IO_FILTER_GROUP, filterGroup);
}
