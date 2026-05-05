/***********************************************************************************************************************************
Zero-Terminated String Handler

The allocation primitive `zNewInternal` is migrated to `pgbr-core::string_z::new`. The variadic `zNewFmt` and the StringId
formatter `zNewStrId` keep their bodies on the C side because routing `va_list` and `strIdToZN` through the FFI surface would be
more work than the few remaining C lines they replace — same trade-off as `strStcFmt` in `stringStatic.c`.
***********************************************************************************************************************************/
#include <build.h>

#include <stdarg.h>
#include <stdio.h>

#include "common/debug.h"
#include "common/error/error.h"
#include "common/memContext.h"
#include "common/type/object.h"
#include "common/type/stringId.h"
#include "common/type/stringZ.h"
#include "pgbr_ffi.h"

/**********************************************************************************************************************************/
static char *
zNewInternal(const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    FUNCTION_TEST_RETURN(STRINGZ, pgbr_string_z_new(size, errorTryDepth()));
}

/**********************************************************************************************************************************/
FN_EXTERN char *
zNewFmt(const char *const format, ...)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRINGZ, format);
    FUNCTION_TEST_END();

    ASSERT(format != NULL);

    // Determine how long the allocated string needs to be
    va_list argumentList;
    va_start(argumentList, format);
    const size_t size = (size_t)vsnprintf(NULL, 0, format, argumentList) + 1;
    va_end(argumentList);

    // Format string
    char *const result = zNewInternal(size);

    va_start(argumentList, format);
    vsnprintf(result, size, format, argumentList);
    va_end(argumentList);

    FUNCTION_TEST_RETURN(STRINGZ, result);
}

/**********************************************************************************************************************************/
FN_EXTERN char *
zNewStrId(const StringId strId)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING_ID, strId);
    FUNCTION_TEST_END();

    ASSERT(strId != 0);
    ASSERT(MEM_CONTEXT_ALLOC_EXTRA_MAX >= STRID_MAX + 1);

    char *const result = zNewInternal(STRID_MAX + 1);
    result[strIdToZN(strId, result)] = '\0';

    FUNCTION_TEST_RETURN(STRINGZ, result);
}
