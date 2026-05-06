/***********************************************************************************************************************************
Test Log Handler
***********************************************************************************************************************************/
#include <fcntl.h>
#include <unistd.h>

#include <common/regExp.h>

#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Open a log file
***********************************************************************************************************************************/
static int
testLogOpen(const char *logFile, int flags, int mode)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(STRINGZ, logFile);
        FUNCTION_HARNESS_PARAM(INT, flags);
        FUNCTION_HARNESS_PARAM(INT, mode);

        FUNCTION_HARNESS_ASSERT(logFile != NULL);
    FUNCTION_HARNESS_END();

    int result = open(logFile, flags, mode);

    THROW_ON_SYS_ERROR_FMT(result == -1, FileOpenError, "unable to open log file '%s'", logFile);

    FUNCTION_HARNESS_RETURN(INT, result);
}

/***********************************************************************************************************************************
Load log result from file into a buffer
***********************************************************************************************************************************/
static void
testLogLoad(const char *logFile, char *buffer, size_t bufferSize)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(STRINGZ, logFile);
        FUNCTION_HARNESS_PARAM_P(CHARDATA, buffer);
        FUNCTION_HARNESS_PARAM(SIZE, bufferSize);

        FUNCTION_HARNESS_ASSERT(logFile != NULL);
        FUNCTION_HARNESS_ASSERT(buffer != NULL);
    FUNCTION_HARNESS_END();

    buffer[0] = 0;

    int fd = testLogOpen(logFile, O_RDONLY, 0);

    size_t totalBytes = 0;
    ssize_t actualBytes = 0;

    do
    {
        THROW_ON_SYS_ERROR_FMT(
            (actualBytes = read(fd, buffer, bufferSize - totalBytes)) == -1, FileOpenError, "unable to read log file '%s'",
            logFile);

        totalBytes += (size_t)actualBytes;
    }
    while (actualBytes != 0);

    THROW_ON_SYS_ERROR_FMT(close(fd) == -1, FileOpenError, "unable to close log file '%s'", logFile);

    // Remove final linefeed
    buffer[totalBytes - 1] = 0;

    FUNCTION_HARNESS_RETURN_VOID();
}

/***********************************************************************************************************************************
Compare log to a static string
***********************************************************************************************************************************/
static void
testLogResult(const char *logFile, const char *expected)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(STRINGZ, logFile);
        FUNCTION_HARNESS_PARAM(STRINGZ, expected);

        FUNCTION_HARNESS_ASSERT(logFile != NULL);
        FUNCTION_HARNESS_ASSERT(expected != NULL);
    FUNCTION_HARNESS_END();

    char actual[32768];
    testLogLoad(logFile, actual, sizeof(actual));

    TEST_RESULT_Z(actual, expected, "check log");

    FUNCTION_HARNESS_RETURN_VOID();
}

/***********************************************************************************************************************************
Test Run
***********************************************************************************************************************************/
static void
testRun(void)
{
    FUNCTION_HARNESS_VOID();

    // *****************************************************************************************************************************
    if (testBegin("logLevelEnum() and logLevelStr()"))
    {
        TEST_ERROR(logLevelEnum(LOG_LEVEL_MAX), AssertError, "assertion 'logLevelSeq < LOG_LEVEL_MAX' failed");
        TEST_RESULT_INT(logLevelEnum(strIdSeq(strIdSeqFromZ("off", 0))), logLevelOff, "log level 'OFF' found");
        TEST_RESULT_INT(logLevelEnum(strIdSeq(strIdSeqFromZ("info", 3))), logLevelInfo, "log level 'info' found");
        TEST_RESULT_INT(logLevelEnum(strIdSeq(strIdSeqFromZ("trace", 6))), logLevelTrace, "log level 'TRACE' found");

        TEST_ERROR(logLevelStr(999), AssertError, "assertion 'logLevel <= LOG_LEVEL_MAX' failed");
        TEST_RESULT_Z(logLevelStr(logLevelOff), "OFF", "log level 'OFF' found");
        TEST_RESULT_Z(logLevelStr(logLevelInfo), "INFO", "log level 'INFO' found");
        TEST_RESULT_Z(logLevelStr(logLevelTrace), "TRACE", "log level 'TRACE' found");
    }

    // *****************************************************************************************************************************
    if (testBegin("logInit()"))
    {
        TEST_RESULT_INT(pgbr_log_level_std_out_get(), logLevelError, "console logging is error");
        TEST_RESULT_INT(pgbr_log_level_std_err_get(), logLevelError, "stderr logging is error");
        TEST_RESULT_INT(pgbr_log_level_file_get(), logLevelOff, "file logging is off");

        TEST_RESULT_VOID(logInit(logLevelInfo, logLevelWarn, logLevelError, true, 0, 99, true), "init logging");
        TEST_RESULT_INT(pgbr_log_level_std_out_get(), logLevelInfo, "console logging is info");
        TEST_RESULT_INT(pgbr_log_level_std_err_get(), logLevelWarn, "stderr logging is warn");
        TEST_RESULT_INT(pgbr_log_level_file_get(), logLevelError, "file logging is error");
        TEST_RESULT_INT(pgbr_log_process_size_get(), 2, "process field size is 2");
        TEST_RESULT_BOOL(pgbr_log_dry_run_get(), true, "dry run is true");

        TEST_RESULT_VOID(logInit(logLevelInfo, logLevelWarn, logLevelError, true, 0, 100, false), "init logging");
        TEST_RESULT_INT(pgbr_log_process_size_get(), 3, "process field size is 3");
        TEST_RESULT_BOOL(pgbr_log_dry_run_get(), false, "dry run is false");
    }

    // *****************************************************************************************************************************
    if (testBegin("logAny*()"))
    {
        pgbr_log_level_std_out_set(logLevelOff);
        pgbr_log_level_std_err_set(logLevelOff);
        pgbr_log_level_file_set(logLevelOff);
        pgbr_log_fd_file_set(-1);
        TEST_RESULT_VOID(pgbr_log_any_set(), "set log any");
        TEST_RESULT_BOOL(logAny(logLevelError), false, "will not log");

        pgbr_log_level_std_err_set(logLevelError);
        TEST_RESULT_VOID(pgbr_log_any_set(), "set log any");
        TEST_RESULT_BOOL(logAny(logLevelError), true, "will log");

        pgbr_log_level_file_set(logLevelWarn);
        TEST_RESULT_VOID(pgbr_log_any_set(), "set log any");
        TEST_RESULT_BOOL(logAny(logLevelWarn), false, "will not log");

        pgbr_log_fd_file_set(1);
        TEST_RESULT_VOID(pgbr_log_any_set(), "set log any");
        TEST_RESULT_BOOL(logAny(logLevelWarn), true, "will log");
        pgbr_log_fd_file_set(-1);
    }

    // *****************************************************************************************************************************
    // The legacy `testBegin("logWrite()")` was removed in Phase 31 sub-issue B: `logWrite` no longer exists on the C side. The
    // equivalent error path (write to a closed fd surfacing as FileWriteError) is exercised by the `logInternal()` block below
    // through the public API and by `pgbr-core::log::format::tests::log_internal_returns_error_on_invalid_fd`.
    if (testBegin("logInternal() and logInternalFmt()"))
    {
        TEST_RESULT_VOID(logInit(logLevelOff, logLevelOff, logLevelOff, false, 0, 1, false), "init logging to off");
        TEST_RESULT_VOID(
            logInternal(logLevelWarn, LOG_LEVEL_MIN, LOG_LEVEL_MAX, 0, "file", "function", 0, "format"),
            "message not logged anywhere");

        TEST_RESULT_VOID(logInit(logLevelWarn, logLevelOff, logLevelOff, true, 0, 1, false), "init logging to warn (timestamp on)");
        TEST_RESULT_VOID(logFileSet(BOGUS_STR), "ignore bogus filename because file logging is off");
        TEST_RESULT_VOID(
            logInternal(logLevelWarn, LOG_LEVEL_MIN, LOG_LEVEL_MAX, 0, "file", "function", 0, "TEST"), "log timestamp");

        String *logTime = strNewZN(pgbr_log_buffer_ptr(), 23);
        TEST_RESULT_BOOL(
            regExpMatchOne(
                STRDEF("^20[0-9]{2}\\-[0-1][0-9]\\-[0-3][0-9] [0-2][0-9]\\:[0-5][0-9]\\:[0-5][0-9]\\.[0-9]{3}$"), logTime),
            true, "check timestamp format");

        // Redirect output to files
        const char *const stdoutFile = TEST_PATH "/stdout.log";
        pgbr_log_fd_std_out_set(testLogOpen(stdoutFile, O_WRONLY | O_CREAT | O_TRUNC, 0640));

        const char *const stderrFile = TEST_PATH "/stderr.log";
        pgbr_log_fd_std_err_set(testLogOpen(stderrFile, O_WRONLY | O_CREAT | O_TRUNC, 0640));

        TEST_RESULT_VOID(
            logInit(logLevelWarn, logLevelOff, logLevelOff, false, 44, 1, false), "init logging to warn (timestamp off)");

        pgbr_log_buffer_ptr()[0] = 0;
        TEST_RESULT_VOID(
            logInternalFmt(logLevelWarn, LOG_LEVEL_MIN, LOG_LEVEL_MAX, UINT_MAX, "file", "function", 0, "format %d", 99),
            "log warn");
        TEST_RESULT_Z(pgbr_log_buffer_ptr(), "P44   WARN: format 99\n", "    check log");

        // This won't be logged due to the range
        TEST_RESULT_VOID(
            logInternal(logLevelWarn, logLevelError, logLevelError, UINT_MAX, "file", "function", 0, "NOT OUTPUT"), "out of range");

        pgbr_log_buffer_ptr()[0] = 0;
        TEST_RESULT_VOID(
            logInternal(logLevelError, LOG_LEVEL_MIN, LOG_LEVEL_MAX, UINT_MAX, "file", "function", 26, "message"), "log error");
        TEST_RESULT_Z(pgbr_log_buffer_ptr(), "P44  ERROR: [026]: message\n", "    check log");

        pgbr_log_buffer_ptr()[0] = 0;
        TEST_RESULT_VOID(
            logInternal(logLevelError, LOG_LEVEL_MIN, LOG_LEVEL_MAX, UINT_MAX, "file", "function", 26, "message1\nmessage2"),
            "log error with multiple lines");
        TEST_RESULT_Z(pgbr_log_buffer_ptr(), "P44  ERROR: [026]: message1\nmessage2\n", "    check log");

        TEST_RESULT_VOID(logInit(logLevelDebug, logLevelDebug, logLevelDebug, false, 0, 999, false), "init logging to debug");

        // Log to file
        const char *const fileFile = TEST_PATH "/file.log";
        logFileSet(fileFile);

        pgbr_log_buffer_ptr()[0] = 0;
        TEST_RESULT_VOID(
            logInternal(
                logLevelDebug, LOG_LEVEL_MIN, LOG_LEVEL_MAX, 999, "test.c", "test_func", 0, "message\nmessage2"), "log debug");
        TEST_RESULT_Z(pgbr_log_buffer_ptr(), "P999  DEBUG:     test::test_func: message\nmessage2\n", "    check log");

        // This won't be logged due to the range
        TEST_RESULT_VOID(
            logInternal(logLevelDebug, logLevelTrace, logLevelTrace, UINT_MAX, "test.c", "test_func", 0, "NOT OUTPUT"),
            "out of range");

        pgbr_log_buffer_ptr()[0] = 0;
        TEST_RESULT_VOID(
            logInternal(logLevelTrace, LOG_LEVEL_MIN, LOG_LEVEL_MAX, UINT_MAX, "test.c", "test_func", 0, "message"), "log debug");
        TEST_RESULT_Z(pgbr_log_buffer_ptr(), "P000  TRACE:         test::test_func: message\n", "    check log");

        // Reopen the log file
        TEST_RESULT_VOID(
            logInit(logLevelDebug, logLevelDebug, logLevelDebug, false, 0, 99, true), "reduce process-id size and dry-run");
        TEST_RESULT_BOOL(logFileSet(fileFile), true, "open valid file");

        pgbr_log_buffer_ptr()[0] = 0;
        TEST_RESULT_VOID(
            logInternal(logLevelInfo, LOG_LEVEL_MIN, LOG_LEVEL_MAX, 1, "test.c", "test_func", 0, "info message"), "log info");
        TEST_RESULT_Z(pgbr_log_buffer_ptr(), "P01   INFO: [DRY-RUN] info message\n", "    check log");
        TEST_RESULT_VOID(
            logInternal(logLevelInfo, LOG_LEVEL_MIN, LOG_LEVEL_MAX, 99, "test.c", "test_func", 0, "info message 2"), "log info");
        TEST_RESULT_Z(pgbr_log_buffer_ptr(), "P99   INFO: [DRY-RUN] info message 2\n", "    check log");

        // Reopen invalid log file
        TEST_RESULT_BOOL(logFileSet("/" BOGUS_STR), false, "attempt to open bogus file");
        TEST_RESULT_INT(pgbr_log_fd_file_get(), -1, "log file is closed");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("error goes to stderr when stderr is not in range but stdout is");

        TEST_RESULT_VOID(logInit(logLevelDebug, logLevelWarn, logLevelOff, false, 0, 99, false), "init");
        TEST_RESULT_VOID(
            logInternal(logLevelError, logLevelDebug, LOG_LEVEL_MAX, 99, "test.c", "test_func", 1, "error to stderr"), "log error");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("error goes to stderr when stdout is not in range but stderr is");

        TEST_RESULT_VOID(logInit(logLevelWarn, logLevelDebug, logLevelOff, false, 0, 99, false), "init");
        TEST_RESULT_VOID(
            logInternal(logLevelError, logLevelDebug, LOG_LEVEL_MAX, 99, "test.c", "test_func", 1, "error to stderr 2"),
            "log error");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("error goes nowhere when stdout and stderr are out of rance");

        TEST_RESULT_VOID(logInit(logLevelWarn, logLevelDebug, logLevelOff, false, 0, 99, false), "init");
        TEST_RESULT_VOID(
            logInternal(logLevelError, logLevelTrace, LOG_LEVEL_MAX, 99, "test.c", "test_func", 1, "error to stderr 2"),
            "log error");

        // Get the error message from above to use for the expect log test
        int testFdFile = open("/" BOGUS_STR, O_CREAT | O_APPEND, 0640);
        const char *testErrorFile = strerror(errno);
        TEST_RESULT_INT(testFdFile, -1, "got error message");

        // Close logging again
        TEST_RESULT_VOID(logInit(logLevelDebug, logLevelDebug, logLevelDebug, false, 0, 99, false), "reduce log size");
        TEST_RESULT_BOOL(logFileSet(fileFile), true, "open valid file");
        TEST_RESULT_BOOL(pgbr_log_fd_file_get() != -1, true, "log file is open");

        logClose();
        TEST_RESULT_INT(pgbr_log_level_std_out_get(), logLevelOff, "console logging is off");
        TEST_RESULT_INT(pgbr_log_level_std_err_get(), logLevelOff, "stderr logging is off");
        TEST_RESULT_INT(pgbr_log_level_file_get(), logLevelOff, "file logging is off");
        TEST_RESULT_INT(pgbr_log_fd_file_get(), -1, "log file is closed");

        // Check stdout
        testLogResult(
            stdoutFile,
            "P44   WARN: format 99\n"
            "P44  ERROR: [026]: message\n"
            "P44  ERROR: [026]: message1\n"
            "            message2");

        // Check stderr
        char buffer[4096];

        sprintf(
            buffer,
            "DEBUG:     test::test_func: message\n"
            "           message2\n"
            "INFO: [DRY-RUN] info message\n"
            "INFO: [DRY-RUN] info message 2\n"
            "WARN: [DRY-RUN] unable to open log file '/BOGUS': %s\n"
            "      NOTE: process will continue without log file.\n"
            "ERROR: [001]: error to stderr\n"
            "ERROR: [001]: error to stderr 2",
            testErrorFile);

        testLogResult(stderrFile, buffer);

        // Check file
        testLogResult(
            fileFile,
            "-------------------PROCESS START-------------------\n"
            "P999  DEBUG:     test::test_func: message\n"
            "                 message2\n"
            "\n"
            "-------------------PROCESS START-------------------\n"
            "P01   INFO: [DRY-RUN] info message\n"
            "P99   INFO: [DRY-RUN] info message 2");
    }

    // *****************************************************************************************************************************
    if (testBegin("logSignal()"))
    {
        TEST_RESULT_VOID(logInit(logLevelDebug, logLevelDebug, logLevelDebug, false, 0, 999, false), "init logging to debug");

        TEST_RESULT_VOID(logSignal(logLevelDebug, "SIGNAL_NAME"), "log debug");
        TEST_RESULT_Z(pgbr_log_buffer_ptr(), "terminated on signal SIGNAL_NAME\n", "check log");
    }

    FUNCTION_HARNESS_RETURN_VOID();
}
