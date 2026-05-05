/***********************************************************************************************************************************
String Handler

Thin C shims over `pgbr-core::string`. The `StringPub` layout (size + extra bitfields packed into a u64, then `char *buffer`) is
mirrored byte-for-byte by the Rust side; the public `typedef struct String String;` keeps the layout opaque to external callers
while the inline `strSize` / `strZ` accessors continue to work via the existing `THIS_PUB(String)` macro.

Variadic constructors (`strNewFmt`, `strCatFmt`) keep their bodies on the C side — same precedent as `strStcFmt` (Phase 34) and
`zNewFmt` (Phase 35): routing `va_list` through the FFI surface would be more code than the few remaining C lines they replace.
The cross-module entry points (`strNewBuf`, `strNewEncode`, `strNewTime`, `strNewDiv`, `strNewPct`, `strNewStrId`, `strCatBuf`,
`strCatEncode`, `strCatTime`, `strSizeFormat`, `strPathAbsolute`, `strToLog`) keep their structure too — they reach into Buffer /
encode / cvt / StringList / strStc helpers that live elsewhere — but every actual `String` mutation goes through the FFI shims.
***********************************************************************************************************************************/
#include <build.h>

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "common/debug.h"
#include "common/error/error.h"
#include "common/macro.h"
#include "common/memContext.h"
#include "common/type/string.h"
#include "common/type/stringList.h"
#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Constant strings that are generally useful
***********************************************************************************************************************************/
STRING_EXTERN(CR_STR,                                               "\r");
STRING_EXTERN(CRLF_STR,                                             "\r\n");
STRING_EXTERN(DOT_STR,                                              ".");
STRING_EXTERN(DOTDOT_STR,                                           "..");
STRING_EXTERN(EMPTY_STR,                                            "");
STRING_EXTERN(FALSE_STR,                                            FALSE_Z);
STRING_EXTERN(FSLASH_STR,                                           "/");
STRING_EXTERN(LF_STR,                                               "\n");
STRING_EXTERN(N_STR,                                                "n");
STRING_EXTERN(NULL_STR,                                             NULL_Z);
STRING_EXTERN(TRUE_STR,                                             TRUE_Z);
STRING_EXTERN(Y_STR,                                                "y");
STRING_EXTERN(ZERO_STR,                                             "0");

/***********************************************************************************************************************************
Object type — kept here so the C ABI keeps `sizeof(String)` resolvable. The Rust side owns the canonical layout via `#[repr(C)]`
on `StringPub` (same field order, same bitfield packing).
***********************************************************************************************************************************/
struct String
{
    StringPub pub;                                                  // Publicly accessible variables
};

// Build-time check that the C `StringPub` size matches what the Rust mirror assumes (two pointer-sized words on every supported
// platform). Wrapped in a static-asserting struct so it stays at file scope.
typedef char check_StringPub_size[sizeof(StringPub) == 2 * sizeof(void *) ? 1 : -1];

/***********************************************************************************************************************************
Maximum size of a string — kept here for the C-side CHECK_SIZE macro callers (the test asserts the boundary directly via the
macro, and other modules text-include this file).
***********************************************************************************************************************************/
#define STRING_SIZE_MAX                                            1073741824

#define CHECK_SIZE(size)                                                                                                           \
    do                                                                                                                             \
    {                                                                                                                              \
        if ((size) > STRING_SIZE_MAX)                                                                                              \
            THROW(AssertError, "string size must be <= " STRINGIFY(STRING_SIZE_MAX) " bytes");                                     \
    }                                                                                                                              \
    while (0)

/***********************************************************************************************************************************
strResize is consumed by `src/build/common/string.c` (which text-includes this file and adds the build-time `strReplace` helper).
Keep the C-side name as a static shim around the FFI export so the build module keeps compiling. The `unused` attribute keeps the
warning quiet for translation units that include `string.c` without needing strReplace's path (the main pgbackrust binary).
***********************************************************************************************************************************/
__attribute__((unused)) static void
strResize(String *const this, const size_t requested)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(SIZE, requested);
    FUNCTION_TEST_END();

    pgbr_string_resize(this, requested, errorTryDepth(), EMPTY_STR->pub.buffer);

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strNew(void)
{
    FUNCTION_TEST_VOID();

    FUNCTION_TEST_RETURN(STRING, pgbr_string_new(EMPTY_STR->pub.buffer, errorTryDepth()));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strNewZ(const char *const string)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRINGZ, string);
    FUNCTION_TEST_END();

    ASSERT(string != NULL);

    FUNCTION_TEST_RETURN(STRING, pgbr_string_new_z(string, errorTryDepth()));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strNewZN(const char *const string, const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(CHARDATA, string);
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    ASSERT(string != NULL);

    FUNCTION_TEST_RETURN(STRING, pgbr_string_new_zn(string, size, errorTryDepth()));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strNewBuf(const Buffer *const buffer)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(BUFFER, buffer);
    FUNCTION_TEST_END();

    ASSERT(buffer != NULL);

    FUNCTION_TEST_RETURN(STRING, pgbr_string_new_zn((const char *)bufPtrConst(buffer), bufUsed(buffer), errorTryDepth()));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strNewDiv(const uint64_t dividend, const uint64_t divisor, StrNewDivParam param)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(UINT64, dividend);
        FUNCTION_TEST_PARAM(UINT64, divisor);
        FUNCTION_TEST_PARAM(UINT, param.precision);
        FUNCTION_TEST_PARAM(BOOL, param.trim);
    FUNCTION_TEST_END();

    char working[CVT_DIV_BUFFER_SIZE];

    size_t resultSize = cvtDivToZ(dividend, divisor, param.precision, param.trim, working, sizeof(working));

    FUNCTION_TEST_RETURN(STRING, strNewZN(working, resultSize));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strNewPct(const uint64_t dividend, const uint64_t divisor)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(UINT64, dividend);
        FUNCTION_TEST_PARAM(UINT64, divisor);
    FUNCTION_TEST_END();

    char working[CVT_PCT_BUFFER_SIZE];

    size_t resultSize = cvtPctToZ(dividend, divisor, working, sizeof(working));

    FUNCTION_TEST_RETURN(STRING, strNewZN(working, resultSize));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strNewStrId(const StringId strId)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING_ID, strId);
    FUNCTION_TEST_END();

    char buffer[STRID_MAX + 1];
    const size_t size = strIdToZN(strId, buffer);
    buffer[size] = '\0';

    FUNCTION_TEST_RETURN(STRING, strNewZN(buffer, size));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strNewTime(const char *const format, const time_t timestamp, const StrNewTimeParam param)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRINGZ, format);
        FUNCTION_TEST_PARAM(TIME, timestamp);
        FUNCTION_TEST_PARAM(BOOL, param.utc);
    FUNCTION_TEST_END();

    char buffer[64];

    // We can ignore this warning here since the format parameter of strNewTimeP() is checked
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
    cvtTimeToZP(format, timestamp, buffer, sizeof(buffer), .utc = param.utc);
#pragma GCC diagnostic pop

    FUNCTION_TEST_RETURN(STRING, strNewZ(buffer));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strNewEncode(const EncodingType type, const Buffer *const buffer)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ENUM, type);
        FUNCTION_TEST_PARAM(BUFFER, buffer);
    FUNCTION_TEST_END();

    ASSERT(buffer != NULL);

    // Create object via Rust path; the buffer is sized for `encodeToStrSize` bytes plus the trailing NUL.
    String *const this = pgbr_string_new_fixed(encodeToStrSize(type, bufUsed(buffer)), errorTryDepth());

    // Encode buffer
    if (bufUsed(buffer) > 0)
    {
        encodeToStr(type, bufPtrConst(buffer), bufUsed(buffer), this->pub.buffer);
    }
    // Else zero-terminate
    else
        this->pub.buffer[0] = '\0';

    FUNCTION_TEST_RETURN(STRING, this);
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strNewFmt(const char *const format, ...)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRINGZ, format);
    FUNCTION_TEST_END();

    ASSERT(format != NULL);

    // Determine how long the allocated string needs to be and create object
    va_list argumentList;
    va_start(argumentList, format);
    String *const this = pgbr_string_new_fixed((size_t)vsnprintf(NULL, 0, format, argumentList), errorTryDepth());
    va_end(argumentList);

    // Format string
    va_start(argumentList, format);
    vsnprintf(this->pub.buffer, strSize(this) + 1, format, argumentList);
    va_end(argumentList);

    FUNCTION_TEST_RETURN(STRING, this);
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strBase(const String *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(STRING, strNewZ(strBaseZ(this)));
}

FN_EXTERN const char *
strBaseZ(const String *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN_CONST(STRINGZ, pgbr_string_base_z(this));
}

/**********************************************************************************************************************************/
FN_EXTERN bool
strBeginsWith(const String *const this, const String *const beginsWith)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(STRING, beginsWith);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(beginsWith != NULL);

    FUNCTION_TEST_RETURN(BOOL, strBeginsWithZ(this, strZ(beginsWith)));
}

FN_EXTERN bool
strBeginsWithZ(const String *const this, const char *const beginsWith)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(STRINGZ, beginsWith);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(beginsWith != NULL);

    FUNCTION_TEST_RETURN(BOOL, pgbr_string_begins_with_z(this, beginsWith));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strCat(String *const this, const String *const cat)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(STRING, cat);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(cat != NULL);

    FUNCTION_TEST_RETURN(STRING, strCatZN(this, strZ(cat), strSize(cat)));
}

FN_EXTERN String *
strCatZ(String *const this, const char *const cat)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(STRINGZ, cat);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(cat != NULL);

    FUNCTION_TEST_RETURN(STRING, pgbr_string_cat_z(this, cat, errorTryDepth(), EMPTY_STR->pub.buffer));
}

FN_EXTERN String *
strCatZN(String *const this, const char *const cat, const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(STRINGZ, cat);
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(size == 0 || cat != NULL);

    FUNCTION_TEST_RETURN(STRING, pgbr_string_cat_zn(this, cat, size, errorTryDepth(), EMPTY_STR->pub.buffer));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strCatBuf(String *const this, const Buffer *const buffer)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(BUFFER, buffer);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(buffer != NULL);

    FUNCTION_TEST_RETURN(STRING, strCatZN(this, (const char *)bufPtrConst(buffer), bufUsed(buffer)));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strCatChr(String *const this, const char cat)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(CHAR, cat);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(cat != 0);

    FUNCTION_TEST_RETURN(STRING, pgbr_string_cat_chr(this, cat, errorTryDepth(), EMPTY_STR->pub.buffer));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strCatEncode(String *const this, const EncodingType type, const Buffer *const buffer)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(ENUM, type);
        FUNCTION_TEST_PARAM(BUFFER, buffer);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(buffer != NULL);

    const size_t encodeSize = encodeToStrSize(type, bufUsed(buffer));

    if (encodeSize != 0)
    {
        // Ensure there is enough space to grow the string
        pgbr_string_resize(this, encodeSize, errorTryDepth(), EMPTY_STR->pub.buffer);

        // Append the encoded string
        encodeToStr(type, bufPtrConst(buffer), bufUsed(buffer), this->pub.buffer + strSize(this));

        // Update size/extra
        this->pub.size += (unsigned int)encodeSize;
        this->pub.extra -= (unsigned int)encodeSize;
    }

    FUNCTION_TEST_RETURN(STRING, this);
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strCatTime(String *const this, const char *const format, const time_t timestamp, const StrCatTimeParam param)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(STRINGZ, format);
        FUNCTION_TEST_PARAM(TIME, timestamp);
        FUNCTION_TEST_PARAM(BOOL, param.utc);
    FUNCTION_TEST_END();

    char buffer[64];

    // We can ignore this warning here since the format parameter of strCatTimeP() is checked
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
    cvtTimeToZP(format, timestamp, buffer, sizeof(buffer), .utc = param.utc);
#pragma GCC diagnostic pop

    FUNCTION_TEST_RETURN(STRING, strCatZ(this, buffer));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strCatFmt(String *const this, const char *const format, ...)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(STRINGZ, format);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(format != NULL);

    // Determine how long the allocated string needs to be
    va_list argumentList;
    va_start(argumentList, format);
    const size_t sizeGrow = (size_t)vsnprintf(NULL, 0, format, argumentList);
    va_end(argumentList);

    if (sizeGrow != 0)
    {
        // Ensure there is enough space to grow the string
        pgbr_string_resize(this, sizeGrow, errorTryDepth(), EMPTY_STR->pub.buffer);

        // Append the formatted string
        va_start(argumentList, format);
        vsnprintf(this->pub.buffer + strSize(this), sizeGrow + 1, format, argumentList);
        va_end(argumentList);

        this->pub.size += (unsigned int)sizeGrow;
        this->pub.extra -= (unsigned int)sizeGrow;
    }

    FUNCTION_TEST_RETURN(STRING, this);
}

/**********************************************************************************************************************************/
FN_EXTERN int
strCmp(const String *const this, const String *const compare)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(STRING, compare);
    FUNCTION_TEST_END();

    FUNCTION_TEST_RETURN(INT, pgbr_string_cmp(this, compare));
}

FN_EXTERN int
strCmpZ(const String *const this, const char *const compare)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(STRINGZ, compare);
    FUNCTION_TEST_END();

    FUNCTION_TEST_RETURN(INT, strCmp(this, compare == NULL ? NULL : STR(compare)));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strDup(const String *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
    FUNCTION_TEST_END();

    FUNCTION_TEST_RETURN(STRING, pgbr_string_dup(this, errorTryDepth()));
}

/**********************************************************************************************************************************/
FN_EXTERN bool
strEmpty(const String *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
    FUNCTION_TEST_END();

    FUNCTION_TEST_RETURN(BOOL, pgbr_string_empty(this));
}

/**********************************************************************************************************************************/
FN_EXTERN bool
strEndsWith(const String *const this, const String *const endsWith)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(STRING, endsWith);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(endsWith != NULL);

    FUNCTION_TEST_RETURN(BOOL, strEndsWithZ(this, strZ(endsWith)));
}

FN_EXTERN bool
strEndsWithZ(const String *const this, const char *const endsWith)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(STRINGZ, endsWith);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(endsWith != NULL);

    FUNCTION_TEST_RETURN(BOOL, pgbr_string_ends_with_z(this, endsWith));
}

/**********************************************************************************************************************************/
FN_EXTERN bool
strEq(const String *const this, const String *const compare)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(STRING, compare);
    FUNCTION_TEST_END();

    FUNCTION_TEST_RETURN(BOOL, pgbr_string_eq(this, compare));
}

FN_EXTERN bool
strEqZ(const String *const this, const char *const compare)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(STRINGZ, compare);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(compare != NULL);

    FUNCTION_TEST_RETURN(BOOL, pgbr_string_eq_z(this, compare));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strFirstUpper(String *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(STRING, pgbr_string_first_upper(this));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strFirstLower(String *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(STRING, pgbr_string_first_lower(this));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strLower(String *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(STRING, pgbr_string_lower(this));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strPath(const String *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    const char *end = this->pub.buffer + strSize(this);

    while (end > this->pub.buffer && *(end - 1) != '/')
        end--;

    FUNCTION_TEST_RETURN(
        STRING,
        strNewZN(
            this->pub.buffer,
            end - this->pub.buffer <= 1 ? (size_t)(end - this->pub.buffer) : (size_t)(end - this->pub.buffer - 1)));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strPathAbsolute(const String *const this, const String *const base)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(STRING, base);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    String *result = NULL;

    // Path is already absolute so just return it
    if (strBeginsWith(this, FSLASH_STR))
    {
        result = strDup(this);
    }
    // Else we'll need to construct the absolute path. You would hope we could use realpath() here but it is so broken in the Posix
    // spec that is seems best avoided.
    else
    {
        ASSERT(base != NULL);

        // Base must be absolute to start
        if (!strBeginsWith(base, FSLASH_STR))
            THROW_FMT(AssertError, "base path '%s' is not absolute", strZ(base));

        MEM_CONTEXT_TEMP_BEGIN()
        {
            StringList *const baseList = strLstNewSplit(base, FSLASH_STR);
            StringList *const pathList = strLstNewSplit(this, FSLASH_STR);

            while (!strLstEmpty(pathList))
            {
                const String *const pathPart = strLstGet(pathList, 0);

                // If the last part is empty
                if (strSize(pathPart) == 0)
                {
                    // Allow when this is the last part since it just means there was a trailing /
                    if (strLstSize(pathList) == 1)
                    {
                        strLstRemoveIdx(pathList, 0);
                        break;
                    }

                    THROW_FMT(AssertError, "'%s' is not a valid relative path", strZ(this));
                }

                if (strEq(pathPart, DOTDOT_STR))
                {
                    const String *const basePart = strLstGet(baseList, strLstSize(baseList) - 1);

                    if (strSize(basePart) == 0)
                        THROW_FMT(AssertError, "relative path '%s' goes back too far in base path '%s'", strZ(this), strZ(base));

                    strLstRemoveIdx(baseList, strLstSize(baseList) - 1);
                }
                else if (!strEq(pathPart, DOT_STR))
                    strLstAdd(baseList, pathPart);

                strLstRemoveIdx(pathList, 0);
            }

            MEM_CONTEXT_PRIOR_BEGIN()
            {
                if (strLstSize(baseList) == 1)
                    result = strDup(FSLASH_STR);
                else
                    result = strLstJoin(baseList, "/");
            }
            MEM_CONTEXT_PRIOR_END();
        }
        MEM_CONTEXT_TEMP_END();
    }

    // There should not be any stray .. or // in the final result
    if (strstr(strZ(result), "/..") != NULL || strstr(strZ(result), "//") != NULL)
        THROW_FMT(AssertError, "result path '%s' is not absolute", strZ(result));

    FUNCTION_TEST_RETURN(STRING, result);
}

/**********************************************************************************************************************************/
FN_EXTERN const char *
strZNull(const String *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
    FUNCTION_TEST_END();

    FUNCTION_TEST_RETURN_CONST(STRINGZ, this == NULL ? NULL : strZ(this));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strReplaceChr(String *const this, const char find, const char replace)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(CHAR, find);
        FUNCTION_TEST_PARAM(CHAR, replace);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(STRING, pgbr_string_replace_chr(this, find, replace));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strSub(const String *const this, const size_t start)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(SIZE, start);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(start <= this->pub.size);

    FUNCTION_TEST_RETURN(STRING, strSubN(this, start, strSize(this) - start));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strSubN(const String *const this, const size_t start, const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(SIZE, start);
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(start <= strSize(this));
    ASSERT(start + size <= strSize(this));

    FUNCTION_TEST_RETURN(STRING, strNewZN(strZ(this) + start, size));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strTrim(String *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(STRING, pgbr_string_trim(this));
}

/**********************************************************************************************************************************/
FN_EXTERN int
strChr(const String *const this, const char chr)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
        FUNCTION_TEST_PARAM(CHAR, chr);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(INT, pgbr_string_chr(this, chr));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strTruncIdx(String *const this, const int idx)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(idx >= 0 && (size_t)idx <= strSize(this));

    FUNCTION_TEST_RETURN(STRING, pgbr_string_trunc_idx(this, idx));
}

/**********************************************************************************************************************************/
FN_EXTERN void
strToLog(const String *const this, StringStatic *const debugLog)
{
    strStcFmt(debugLog, "{\"%s\"}", strZ(this));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
strSizeFormat(const uint64_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(UINT64, size);
    FUNCTION_TEST_END();

    String *result;

    if (size < 1024)
        result = strNewFmt("%" PRIu64 "B", size);
    else
    {
        char working[CVT_DIV_BUFFER_SIZE];
        uint64_t divisor = 1024 * 1024 * 1024;
        unsigned int precision = 1;
        const char *suffix = "GB";

        if (size < (1024 * 1024))
        {
            divisor = 1024;
            suffix = "KB";
        }
        else if (size < (1024 * 1024 * 1024))
        {
            divisor = 1024 * 1024;
            suffix = "MB";
        }

        // Skip precision when it would cause overflow
        if (size > UINT64_MAX / 10)
            precision = 0;

        // Format size
        cvtDivToZ(size, divisor, precision, true, working, sizeof(working));
        result = strNewFmt("%s%s", working, suffix);
    }

    FUNCTION_TEST_RETURN(STRING, result);
}
