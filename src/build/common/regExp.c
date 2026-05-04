/***********************************************************************************************************************************
Regular Expression Handler Extensions
***********************************************************************************************************************************/
// Include core module
#include "common/regExp.c"

#include "build/common/regExp.h"

/***********************************************************************************************************************************
Getters/Setters
***********************************************************************************************************************************/
const char *
regExpMatchPtr(RegExp *const this, const String *const string)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(REGEXP, this);
        FUNCTION_TEST_PARAM(STRING, string);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(string != NULL);

    // Test for a match through the Rust shim. The shim returns the byte offsets of the first match (POSIX rm_so / rm_eo
    // equivalent) for the build-time helpers used by uncrustify lints and log harness scrubbing.
    size_t matchStart = 0;
    size_t matchEnd = 0;
    const int32_t result = pgbr_regex_match_offsets(this->handle, strZ(string), &matchStart, &matchEnd);

    if (result < 0)
        THROW_FMT(FormatError, "%s", pgbr_last_error_msg());

    if (result == 1)
        FUNCTION_TEST_RETURN_CONST(STRINGZ, strZ(string) + matchStart);

    // Return NULL when no match
    FUNCTION_TEST_RETURN_CONST(STRINGZ, NULL);
}

String *
regExpMatchStr(RegExp *const this, const String *const string)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(REGEXP, this);
        FUNCTION_TEST_PARAM(STRING, string);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(string != NULL);

    // Test for a match through the Rust shim and rebuild the matched substring as a `String *` in the caller's memory context.
    size_t matchStart = 0;
    size_t matchEnd = 0;
    const int32_t result = pgbr_regex_match_offsets(this->handle, strZ(string), &matchStart, &matchEnd);

    if (result < 0)
        THROW_FMT(FormatError, "%s", pgbr_last_error_msg());

    if (result == 1)
        FUNCTION_TEST_RETURN(STRING, strNewZN(strZ(string) + matchStart, matchEnd - matchStart));

    // Return NULL when no match
    FUNCTION_TEST_RETURN(STRING, NULL);
}
