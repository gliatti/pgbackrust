/***********************************************************************************************************************************
Log Handler

Thin C shims over the Rust state and formatter owned by `crates/pgbr-core::log`.

Sub-issue A migrated the file-scope state (4 levels, 3 fds, banner / timestamp / dry-run flags, process metadata, the 32 KiB
scratchpad) into Rust. Sub-issue B (this revision) hoists the line formatter as well — `logPre` / `logPost` /
`logWriteIndent` / `logWrite` / `logRange` are gone; `logInternal` / `logInternalFmt` / `logSignal` shrink to FFI shims that
delegate to `pgbr_log_internal` / `pgbr_log_internal_fmt` / `pgbr_log_signal` and re-throw via `pgbr_error_throw_from_last` on
write failure. `logFileSet` keeps the `open(2)` syscall and the `LOG_WARN_FMT` failure path on the C side (POSIX I/O remains a
C build concern).

The variadic `logInternalFmt` reuses the format-args marshaller `errorMarshalArgs` defined in `src/common/error/error.c`. Both
THROW_FMT and LOG_*_FMT funnel into the same Rust formatter (`pgbr_error::format::format_message`) — sharing the marshaller
keeps the C-side spec parser single-sourced.
***********************************************************************************************************************************/
#include <build.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>

#include "common/debug.h"
#include "common/error/error.h"
#include "common/log.h"
#include "common/macro.h"
#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Test Asserts
***********************************************************************************************************************************/
#define ASSERT_LOG_LEVEL(logLevel)                                                                                                 \
    ASSERT(logLevel >= LOG_LEVEL_MIN && logLevel <= LOG_LEVEL_MAX)

/**********************************************************************************************************************************/
FN_EXTERN LogLevel
logLevelEnum(unsigned int logLevelSeq)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(UINT, logLevelSeq);
    FUNCTION_TEST_END();

    ASSERT(logLevelSeq < LOG_LEVEL_MAX);

    FUNCTION_TEST_RETURN(ENUM, (LogLevel)pgbr_log_level_enum(logLevelSeq));
}

FN_EXTERN const char *
logLevelStr(const LogLevel logLevel)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ENUM, logLevel);
    FUNCTION_TEST_END();

    ASSERT(logLevel <= LOG_LEVEL_MAX);

    FUNCTION_TEST_RETURN_CONST(STRINGZ, pgbr_log_level_str((int)logLevel));
}

/**********************************************************************************************************************************/
FN_EXTERN bool
logAny(const LogLevel logLevel)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ENUM, logLevel);
    FUNCTION_TEST_END();

    ASSERT_LOG_LEVEL(logLevel);

    FUNCTION_TEST_RETURN(BOOL, pgbr_log_any((int)logLevel));
}

/**********************************************************************************************************************************/
FN_EXTERN void
logInit(
    const LogLevel logLevelStdOutParam, const LogLevel logLevelStdErrParam, const LogLevel logLevelFileParam,
    const bool logTimestampParam, const unsigned int processId, const unsigned int logProcessMax, const bool dryRunParam)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ENUM, logLevelStdOutParam);
        FUNCTION_TEST_PARAM(ENUM, logLevelStdErrParam);
        FUNCTION_TEST_PARAM(ENUM, logLevelFileParam);
        FUNCTION_TEST_PARAM(BOOL, logTimestampParam);
        FUNCTION_TEST_PARAM(UINT, processId);
        FUNCTION_TEST_PARAM(UINT, logProcessMax);
        FUNCTION_TEST_PARAM(BOOL, dryRunParam);
    FUNCTION_TEST_END();

    ASSERT(logLevelStdOutParam <= LOG_LEVEL_MAX);
    ASSERT(logLevelStdErrParam <= LOG_LEVEL_MAX);
    ASSERT(logLevelFileParam <= LOG_LEVEL_MAX);
    ASSERT(processId <= 999);
    ASSERT(logProcessMax <= 999);

    pgbr_log_init(
        (int)logLevelStdOutParam, (int)logLevelStdErrParam, (int)logLevelFileParam, logTimestampParam, processId, logProcessMax,
        dryRunParam);

    FUNCTION_TEST_RETURN_VOID();
}

/***********************************************************************************************************************************
Close the log file
***********************************************************************************************************************************/
static void
logFileClose(void)
{
    FUNCTION_TEST_VOID();

    // Close the file descriptor if it is open
    const int fd = pgbr_log_fd_file_get();

    if (fd != -1)
    {
        close(fd);
        pgbr_log_fd_file_set(-1);
    }

    pgbr_log_any_set();

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN bool
logFileSet(const char *const logFile)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRINGZ, logFile);
    FUNCTION_TEST_END();

    ASSERT(logFile != NULL);

    // Close the log file if it is already open
    logFileClose();

    // Only open the file if there is a chance to log something
    bool result = true;

    if (pgbr_log_level_file_get() != logLevelOff)
    {
        // Open the file and handle errors
        const int fd = open(logFile, O_CREAT | O_APPEND | O_WRONLY, 0640);
        pgbr_log_fd_file_set(fd);

        if (fd == -1)
        {
            const int errNo = errno;
            LOG_WARN_FMT(
                "unable to open log file '%s': %s\nNOTE: process will continue without log file.", logFile, strerror(errNo));
            result = false;
        }

        // Output the banner on first log message
        pgbr_log_file_banner_set(false);

        pgbr_log_any_set();
    }

    pgbr_log_any_set();

    FUNCTION_TEST_RETURN(BOOL, result);
}

/**********************************************************************************************************************************/
FN_EXTERN void
logClose(void)
{
    FUNCTION_TEST_VOID();

    // Disable all logging
    pgbr_log_close();

    // Close the log file if it is open
    logFileClose();

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN void
logSignal(const LogLevel logLevel, const char *const signalName)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ENUM, logLevel);
        FUNCTION_TEST_PARAM(STRINGZ, signalName);
    FUNCTION_TEST_END();

    ASSERT(signalName != NULL);

    if (pgbr_log_signal((int)logLevel, signalName) != 0)
        pgbr_error_throw_from_last(__FILE__, __func__, __LINE__);

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN void
logInternal(
    const LogLevel logLevel, const LogLevel logRangeMin, const LogLevel logRangeMax, const unsigned int processId,
    const char *const fileName, const char *const functionName, const int code, const char *const message)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ENUM, logLevel);
        FUNCTION_TEST_PARAM(ENUM, logRangeMin);
        FUNCTION_TEST_PARAM(ENUM, logRangeMax);
        FUNCTION_TEST_PARAM(UINT, processId);
        FUNCTION_TEST_PARAM(STRINGZ, fileName);
        FUNCTION_TEST_PARAM(STRINGZ, functionName);
        FUNCTION_TEST_PARAM(INT, code);
        FUNCTION_TEST_PARAM(STRINGZ, message);
    FUNCTION_TEST_END();

    ASSERT(message != NULL);

    if (pgbr_log_internal(
            (int)logLevel, (int)logRangeMin, (int)logRangeMax, processId, fileName, functionName, code, message) != 0)
    {
        pgbr_error_throw_from_last(__FILE__, __func__, __LINE__);
    }

    FUNCTION_TEST_RETURN_VOID();
}

FN_EXTERN void
logInternalFmt(
    const LogLevel logLevel, const LogLevel logRangeMin, const LogLevel logRangeMax, const unsigned int processId,
    const char *const fileName, const char *const functionName, const int code, const char *const format, ...)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ENUM, logLevel);
        FUNCTION_TEST_PARAM(ENUM, logRangeMin);
        FUNCTION_TEST_PARAM(ENUM, logRangeMax);
        FUNCTION_TEST_PARAM(UINT, processId);
        FUNCTION_TEST_PARAM(STRINGZ, fileName);
        FUNCTION_TEST_PARAM(STRINGZ, functionName);
        FUNCTION_TEST_PARAM(INT, code);
        FUNCTION_TEST_PARAM(STRINGZ, format);
    FUNCTION_TEST_END();

    ASSERT(format != NULL);

    // Marshal va_args through the same blob format the THROW_FMT path uses (Phase 27 sub-issue B). Reusing
    // errorMarshalArgs keeps the spec parser single-sourced — both routes feed `pgbr_error::format::format_message`.
    PGBR_PgbrFmtArg fmtArgs[ERROR_FMT_ARG_MAX];
    va_list argumentList;
    va_start(argumentList, format);
    const unsigned int nArgs = errorMarshalArgs(format, argumentList, fmtArgs);
    va_end(argumentList);

    if (pgbr_log_internal_fmt(
            (int)logLevel, (int)logRangeMin, (int)logRangeMax, processId, fileName, functionName, code, format, fmtArgs,
            nArgs) != 0)
    {
        pgbr_error_throw_from_last(__FILE__, __func__, __LINE__);
    }

    FUNCTION_TEST_RETURN_VOID();
}
