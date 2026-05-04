/***********************************************************************************************************************************
Regular Expression Handler

Thin C wrappers over the Rust implementation in `crates/pgbr-regex`. The actual matching engine lives in libpgbr_ffi.a; this file
keeps the public API in `src/common/regExp.h` byte-identical to the legacy version, translating between the C calling convention
and the Rust thread-local last-error machinery.
***********************************************************************************************************************************/
#include <build.h>

#include "common/debug.h"
#include "common/regExp.h"
#include "common/type/string.h"
#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Regular expression handle. Holds the opaque pointer returned by the Rust shim plus a memory-context callback that releases it.
***********************************************************************************************************************************/
struct RegExp
{
    void *handle;
};

/***********************************************************************************************************************************
Free regular expression
***********************************************************************************************************************************/
static void
regExpFreeResource(THIS_VOID)
{
    THIS(RegExp);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(REGEXP, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    pgbr_regex_free(this->handle);
    this->handle = NULL;

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN RegExp *
regExpNew(const String *const expression)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, expression);
    FUNCTION_TEST_END();

    ASSERT(expression != NULL);

    OBJ_NEW_BEGIN(RegExp, .childQty = MEM_CONTEXT_QTY_MAX, .callbackQty = 1)
    {
        *this = (RegExp){.handle = NULL};

        // Compile the regexp through the Rust shim. A NULL return populates the thread-local last error, which we re-throw as a
        // FormatError to preserve the legacy throw site.
        this->handle = pgbr_regex_new(strZ(expression));

        if (this->handle == NULL)
            THROW_FMT(FormatError, "%s", pgbr_last_error_msg());

        // Set free callback to release the Rust handle when the memory context is destroyed.
        memContextCallbackSet(objMemContext(this), regExpFreeResource, this);
    }
    OBJ_NEW_END();

    FUNCTION_TEST_RETURN(REGEXP, this);
}

/**********************************************************************************************************************************/
FN_EXTERN bool
regExpMatch(RegExp *const this, const String *const string)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(REGEXP, this);
        FUNCTION_TEST_PARAM(STRING, string);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(string != NULL);

    const int32_t result = pgbr_regex_match(this->handle, strZ(string));

    if (result < 0)
        THROW_FMT(FormatError, "%s", pgbr_last_error_msg());

    FUNCTION_TEST_RETURN(BOOL, result == 1);
}

/**********************************************************************************************************************************/
FN_EXTERN bool
regExpMatchOne(const String *const expression, const String *const string)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, expression);
        FUNCTION_TEST_PARAM(STRING, string);
    FUNCTION_TEST_END();

    ASSERT(expression != NULL);
    ASSERT(string != NULL);

    bool result;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        result = regExpMatch(regExpNew(expression), string);
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_TEST_RETURN(BOOL, result);
}

/**********************************************************************************************************************************/
FN_EXTERN String *
regExpPrefix(const String *const expression)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, expression);
    FUNCTION_TEST_END();

    String *result = NULL;

    if (expression != NULL)
    {
        const size_t prefixLen = pgbr_regex_prefix_len(strZ(expression));

        if (prefixLen == SIZE_MAX)
            THROW_FMT(FormatError, "%s", pgbr_last_error_msg());

        if (prefixLen > 0)
            result = strSubN(expression, 1, prefixLen);
    }

    FUNCTION_TEST_RETURN(STRING, result);
}
