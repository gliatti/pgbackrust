/***********************************************************************************************************************************
Static String Handler

`strStcCat` / `strStcCatChr` route through `pgbr_string_static_*` so the byte-copy + truncation contract lives in
`crates/pgbr-core::string_static`. `strStcFmt` keeps its body in C because it is variadic and consumes the format string with
`vsnprintf`; the C->Rust marshalling bridge for variadic args (`pgbr_error_format_message` from Phase 27 sub-issue B) covers the
THROW_FMT call sites and is overkill for the small buffer-cursor bookkeeping `strStcFmt` performs after the format runs. Final
removal of the C originals is at Phase 212.
***********************************************************************************************************************************/
#include <build.h>

#include <stdarg.h>
#include <stdio.h>

#include "common/type/stringStatic.h"
#include "pgbr_ffi.h"

/**********************************************************************************************************************************/
FN_EXTERN StringStatic *
strStcFmt(StringStatic *const debugLog, const char *const format, ...)
{
    // Proceed if there is space for at least one character
    if (strStcRemainsSize(debugLog) > 1)
    {
        va_list argument;
        va_start(argument, format);
        size_t result = (size_t)vsnprintf(strStcRemains(debugLog), strStcRemainsSize(debugLog), format, argument);
        va_end(argument);

        if (result >= strStcRemainsSize(debugLog))
            debugLog->resultSize = debugLog->bufferSize - 1;
        else
            debugLog->resultSize += result;
    }

    return debugLog;
}

/**********************************************************************************************************************************/
FN_EXTERN void
strStcCat(StringStatic *const debugLog, const char *const cat)
{
    debugLog->resultSize += pgbr_string_static_cat(strStcRemains(debugLog), strStcRemainsSize(debugLog), cat);
}

/**********************************************************************************************************************************/
FN_EXTERN void
strStcCatChr(StringStatic *const debugLog, const char cat)
{
    debugLog->resultSize += pgbr_string_static_cat_chr(strStcRemains(debugLog), strStcRemainsSize(debugLog), cat);
}
