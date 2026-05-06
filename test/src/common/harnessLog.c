/***********************************************************************************************************************************
Log Test Harness

Phase 31 sub-issue C migrated the harness from a `SHIM_MODULE`-based interception of
`src/common/log.c` to an in-memory capture buffer owned by `pgbr_core::log::capture`.
The harness no longer needs the C log internals — `pgbr_log_capture_install` redirects
the file sink to a Rust-side `Vec<u8>` that the harness drains and compares.
***********************************************************************************************************************************/
#include <build.h>

#include <regex.h>
#include <string.h>

#include "build/common/regExp.h"
#include "common/log.h"
#include "common/memContext.h"
#include "common/type/stringList.h"
#include "pgbr_ffi.h"

#include "common/harnessDebug.h"
#include "common/harnessLog.h"
#include "common/harnessTest.h"

/***********************************************************************************************************************************
Log settings for testing
***********************************************************************************************************************************/
static LogLevel logLevelTest = logLevelInfo;
static LogLevel logLevelTestDefault = logLevelOff;
static bool logDryRunTest = false;

/***********************************************************************************************************************************
Buffer where log results are loaded for comparison purposes
***********************************************************************************************************************************/
static char harnessLogBuffer[256 * 1024];

/***********************************************************************************************************************************
Initialize log for testing
***********************************************************************************************************************************/
#ifdef HRN_FEATURE_LOG

void
harnessLogInit(void)
{
    FUNCTION_HARNESS_VOID();

    logInit(logLevelTestDefault, logLevelOff, logLevelInfo, false, pgbr_log_process_id_get(), 99, false);

    // Pre-set the file banner so the test capture does not include the legacy
    // "PROCESS START" banner — tests that explicitly want the banner toggle the flag back
    // off through `pgbr_log_file_banner_set` (e.g. `logTest.c` does this when it calls
    // `logFileSet(fileFile)`).
    pgbr_log_file_banner_set(true);

    // Install the Rust-side capture; it replaces the legacy file fd as the file sink.
    pgbr_log_capture_install();
    pgbr_log_any_set();

    FUNCTION_HARNESS_RETURN_VOID();
}

#endif

/**********************************************************************************************************************************/
void
harnessLogDryRunSet(bool dryRun)
{
    logDryRunTest = dryRun;

    logInit(logLevelTestDefault, logLevelOff, logLevelTest, false, pgbr_log_process_id_get(), 99, logDryRunTest);
}

/**********************************************************************************************************************************/
unsigned int
hrnLogLevelFile(void)
{
    return (unsigned int)pgbr_log_level_file_get();
}

void
hrnLogLevelFileSet(unsigned int logLevel)
{
    pgbr_log_level_file_set((int)logLevel);
}

unsigned int
hrnLogLevelStdOut(void)
{
    return (unsigned int)pgbr_log_level_std_out_get();
}

void
hrnLogLevelStdOutSet(unsigned int logLevel)
{
    pgbr_log_level_std_out_set((int)logLevel);
}

unsigned int
hrnLogLevelStdErr(void)
{
    return (unsigned int)pgbr_log_level_std_err_get();
}

void
hrnLogLevelStdErrSet(unsigned int logLevel)
{
    pgbr_log_level_std_err_set((int)logLevel);
}

/**********************************************************************************************************************************/
bool
hrnLogTimestamp(void)
{
    return pgbr_log_timestamp_get();
}

void
hrnLogTimestampSet(bool log)
{
    pgbr_log_timestamp_set(log);
}

/***********************************************************************************************************************************
Change test log level

This is info by default but it can sometimes be useful to set the log level to something else.
***********************************************************************************************************************************/
void
harnessLogLevelSet(LogLevel logLevel)
{
    logLevelTest = logLevel;

    logInit(logLevelTestDefault, logLevelOff, logLevelTest, false, pgbr_log_process_id_get(), 99, logDryRunTest);
}

/***********************************************************************************************************************************
Reset test log level

Set back to info
***********************************************************************************************************************************/
void
harnessLogLevelReset(void)
{
    logLevelTest = logLevelInfo;

    logInit(logLevelTestDefault, logLevelOff, logLevelTest, false, pgbr_log_process_id_get(), 99, logDryRunTest);
}

/***********************************************************************************************************************************
Change default test log level

Set the default log level for output to the console (for testing).
***********************************************************************************************************************************/
#ifdef HRN_FEATURE_LOG

void
harnessLogLevelDefaultSet(LogLevel logLevel)
{
    logLevelTestDefault = logLevel;
}

/**********************************************************************************************************************************/
void
hrnLogProcessIdSet(unsigned int processId)
{
    pgbr_log_process_id_set(processId);
}

#endif

/***********************************************************************************************************************************
Drain the Rust-side capture buffer into `harnessLogBuffer` and strip the trailing newline so the comparison helpers can work on a
NUL-terminated string. After this call the capture is empty so the next test cycle starts fresh.
***********************************************************************************************************************************/
static void
harnessLogLoad(void)
{
    FUNCTION_HARNESS_VOID();

    const size_t totalBytes = pgbr_log_capture_drain(harnessLogBuffer, sizeof(harnessLogBuffer));

    ASSERT(totalBytes != (size_t)-1);
    ASSERT(totalBytes < sizeof(harnessLogBuffer));

    // Drop the trailing newline written by `log_post` so `strcmp` against the test
    // expectation matches without forcing every test to terminate its expected string
    // with `\n`.
    if (totalBytes > 0 && harnessLogBuffer[totalBytes - 1] == '\n')
        harnessLogBuffer[totalBytes - 1] = 0;

    FUNCTION_HARNESS_RETURN_VOID();
}

/**********************************************************************************************************************************/
static struct
{
    MemContext *memContext;                                         // Mem context for log harness
    List *replaceList;                                              // List of replacements
} harnessLog;

typedef struct HarnessLogReplace
{
    const String *expression;
    RegExp *regExp;
    const String *expressionSub;
    RegExp *regExpSub;
    const String *replacement;
    StringList *matchList;
    bool version;
} HarnessLogReplace;

void
hrnLogReplaceAdd(const char *expression, const char *expressionSub, const char *replacement, bool version)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(STRINGZ, expression);
        FUNCTION_HARNESS_PARAM(STRINGZ, expressionSub);
        FUNCTION_HARNESS_PARAM(STRINGZ, replacement);
        FUNCTION_HARNESS_PARAM(BOOL, version);
    FUNCTION_HARNESS_END();

    FUNCTION_HARNESS_ASSERT(expression != NULL);
    FUNCTION_HARNESS_ASSERT(replacement != NULL);

    if (harnessLog.memContext == NULL)
    {
        MEM_CONTEXT_BEGIN(memContextTop())
        {
            MEM_CONTEXT_NEW_BEGIN(HarnessLog, .childQty = MEM_CONTEXT_QTY_MAX)
            {
                harnessLog.memContext = MEM_CONTEXT_NEW();
            }
            MEM_CONTEXT_NEW_END();
        }
        MEM_CONTEXT_END();
    }

    if (harnessLog.replaceList == NULL)
    {
        MEM_CONTEXT_BEGIN(harnessLog.memContext)
        {
            harnessLog.replaceList = lstNewP(sizeof(HarnessLogReplace));
        }
        MEM_CONTEXT_END();
    }

    MEM_CONTEXT_BEGIN(lstMemContext(harnessLog.replaceList))
    {
        HarnessLogReplace logReplace =
        {
            .expression = strNewZ(expression),
            .regExp = regExpNew(STR(expression)),
            .expressionSub = expressionSub == NULL ? NULL : strNewZ(expressionSub),
            .regExpSub = expressionSub == NULL ? NULL : regExpNew(STR(expressionSub)),
            .replacement = strNewZ(replacement),
            .matchList = strLstNew(),
            .version = version,
        };

        lstAdd(harnessLog.replaceList, &logReplace);
    }
    MEM_CONTEXT_END();

    FUNCTION_HARNESS_RETURN_VOID();
}

void
hrnLogReplaceRemove(const char *const expression)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(STRINGZ, expression);
    FUNCTION_HARNESS_END();

    unsigned int replaceIdx = 0;

    for (; replaceIdx < lstSize(harnessLog.replaceList); replaceIdx++)
    {
        const HarnessLogReplace *const logReplace = lstGet(harnessLog.replaceList, replaceIdx);

        if (strEqZ(logReplace->expression, expression))
        {
            lstRemoveIdx(harnessLog.replaceList, replaceIdx);
            break;
        }
    }

    if (replaceIdx == lstSize(harnessLog.replaceList))
        THROW_FMT(AssertError, "expression '%s' not found in replace list", expression);

    FUNCTION_HARNESS_RETURN_VOID();
}

/**********************************************************************************************************************************/
void
hrnLogReplaceClear(void)
{
    FUNCTION_HARNESS_VOID();

    if (harnessLog.replaceList != NULL)
        lstClear(harnessLog.replaceList);

    FUNCTION_HARNESS_RETURN_VOID();
}

/***********************************************************************************************************************************
Perform log replacements
***********************************************************************************************************************************/
static void
hrnLogReplace(void)
{
    FUNCTION_HARNESS_VOID();

    // Proceed only if replacements have been defined
    if (harnessLog.replaceList != NULL)
    {
        MEM_CONTEXT_TEMP_BEGIN()
        {
            // Loop through all replacements
            for (unsigned int replaceIdx = 0; replaceIdx < lstSize(harnessLog.replaceList); replaceIdx++)
            {
                HarnessLogReplace *logReplace = lstGet(harnessLog.replaceList, replaceIdx);

                // Check for matches
                while (regExpMatch(logReplace->regExp, STRDEF(harnessLogBuffer)))
                {
                    // Get the match
                    String *match = regExpMatchStr(logReplace->regExp, STRDEF(harnessLogBuffer));

                    // Find beginning of match
                    char *begin =
                        harnessLogBuffer + (regExpMatchPtr(logReplace->regExp, STRDEF(harnessLogBuffer)) - harnessLogBuffer);

                    // If there is a sub expression then evaluate it
                    if (logReplace->regExpSub != NULL)
                    {
                        // The sub expression must match
                        if (!regExpMatch(logReplace->regExpSub, match))
                        {
                            THROW_FMT(
                                AssertError, "unable to find sub expression '%s' in '%s' extracted with expression '%s'",
                                strZ(logReplace->expressionSub), strZ(match), strZ(logReplace->expression));
                        }

                        // Find beginning of match
                        begin += regExpMatchPtr(logReplace->regExpSub, match) - strZ(match);

                        // Get the match
                        match = regExpMatchStr(logReplace->regExpSub, match);
                    }

                    // Build replacement string. If versioned then append the version number.
                    String *replace = strCatFmt(strNew(), "[%s", strZ(logReplace->replacement));

                    if (logReplace->version)
                    {
                        unsigned int index = strLstFindIdxP(logReplace->matchList, match);

                        if (index == LIST_NOT_FOUND)
                        {
                            index = strLstSize(logReplace->matchList);
                            strLstAdd(logReplace->matchList, match);
                        }

                        strCatFmt(replace, "-%u", index + 1);
                    }

                    strCatZ(replace, "]");

                    // Find end of match and calculate size difference from replacement
                    char *end = begin + strSize(match);
                    int diff = (int)strSize(replace) - (int)strSize(match);

                    // Make sure we won't overflow the buffer
                    ASSERT((size_t)((int)strlen(harnessLogBuffer) + diff) < sizeof(harnessLogBuffer) - 1);

                    // Move data from end of string enough to make room for the replacement and copy replacement
                    memmove(end + diff, end, strlen(end) + 1);
                    memcpy(begin, strZ(replace), strSize(replace));
                }
            }
        }
        MEM_CONTEXT_TEMP_END();
    }

    FUNCTION_HARNESS_RETURN_VOID();
}

/**********************************************************************************************************************************/
void
harnessLogResult(const char *expected)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(STRINGZ, expected);
    FUNCTION_HARNESS_END();

    ASSERT(expected != NULL);

    harnessLogLoad();
    hrnLogReplace();

    if (strcmp(harnessLogBuffer, expected) != 0)
    {
        THROW_FMT(
            AssertError, "\nACTUAL LOG:\n\n%s\n\nBUT DIFF FROM EXPECTED IS (- remove from expected, + add to expected):\n\n%s",
            harnessLogBuffer, hrnDiff(expected, harnessLogBuffer));
    }

    FUNCTION_HARNESS_RETURN_VOID();
}

/**********************************************************************************************************************************/
void
harnessLogResultEmptyOrContains(const char *const contains)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(STRINGZ, contains);
    FUNCTION_HARNESS_END();

    ASSERT(contains != NULL);

    harnessLogLoad();
    hrnLogReplace();

    if (strlen(harnessLogBuffer) != 0 && strstr(harnessLogBuffer, contains) == NULL)
    {
        THROW_FMT(
            AssertError, "\nLOG MUST CONTAIN:\n\n%s\n\nBUT WAS ACTUALLY:\n\n%s",
            contains, harnessLogBuffer);
    }

    FUNCTION_HARNESS_RETURN_VOID();
}

/***********************************************************************************************************************************
Make sure nothing is left in the log after all tests have completed
***********************************************************************************************************************************/
#ifdef HRN_FEATURE_LOG

void
harnessLogFinal(void)
{
    FUNCTION_HARNESS_VOID();

    harnessLogLoad();
    hrnLogReplace();

    // Tear down the Rust capture so a subsequent test run starts clean.
    pgbr_log_capture_uninstall();

    if (strcmp(harnessLogBuffer, "") != 0)
        THROW_FMT(AssertError, "\n\nexpected log to be empty but actual log was:\n\n%s\n\n", harnessLogBuffer);

    FUNCTION_HARNESS_RETURN_VOID();
}

#endif
