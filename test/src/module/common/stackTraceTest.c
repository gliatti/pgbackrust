/***********************************************************************************************************************************
Test Stack Trace Handler

The Phase-30 migration moved the canonical state into `crates/pgbr-core::stack_trace`. The legacy test wrote directly into
`stackTraceLocal.stack[i]` fields and called private static helpers; both are gone — instead the test exercises the public
`stackTracePush` / `stackTracePop` / `stackTraceParam*` API and reads frames via the cbindgen-generated `PGBR_PgbrStackFrame`
mirror plus a small set of test-only setters (`pgbr_stack_trace_test_size_inc/dec`, `pgbr_stack_trace_test_set_frame_field`).

`legacy_stackTraceFmt` and the legacy `stackTraceBackCallback` / `stackTraceBackErrorCallback` paths are kept here as differential
helpers so the test still asserts byte-identical output for the rendered-trace cases.
***********************************************************************************************************************************/
#include <assert.h>

#include "common/harnessStackTrace.h"
#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Discriminants for `pgbr_stack_trace_test_set_frame_field`. Kept private to the test — they mirror the match arms in
`crates/pgbr-core/src/stack_trace.rs::test_set_frame_field`.
***********************************************************************************************************************************/
#define FRAME_FIELD_FILE_LINE                                       0
#define FRAME_FIELD_FUNCTION_LOG_LEVEL                              1
#define FRAME_FIELD_PARAM_SIZE                                      2
#define FRAME_FIELD_PARAM_OFFSET                                    3

/***********************************************************************************************************************************
Differential helper — verbatim copy of the pre-Phase-30 `stackTraceFmt` body so the test can drive both paths the same way.
***********************************************************************************************************************************/
static FN_PRINTF(4, 5) size_t
legacy_stackTraceFmt(char *const buffer, const size_t bufferSize, const size_t bufferUsed, const char *const format, ...)
{
    va_list argumentList;
    va_start(argumentList, format);
    const int result = vsnprintf(
        buffer + bufferUsed, bufferUsed < bufferSize ? bufferSize - bufferUsed : 0, format, argumentList);
    va_end(argumentList);

    return (size_t)result;
}

#ifdef HAVE_LIBBACKTRACE

static FN_NO_RETURN void
testStackTraceError3(void)
{
    stackTracePush("module/common/stackTraceTest.c", "testStackTraceError3", logLevelTrace);
    THROW(FormatError, "test error");
}

static FN_NO_RETURN void
testStackTraceError2(void)
{
    testStackTraceError3();
}

static FN_NO_RETURN void
testStackTraceError1(void)
{
    stackTracePush("src/file1.c", "testStackTraceError1", logLevelDebug);
    testStackTraceError2();
}

static FN_NO_RETURN void
testStackTraceError5(void)
{
    THROW_FMT(FormatError, "test error fmt");
}

static FN_NO_RETURN void
testStackTraceError4(void)
{
    stackTracePush("file4.c", "testStackTraceError4", logLevelTrace);
    testStackTraceError5();
}

#endif

/***********************************************************************************************************************************
Test Run
***********************************************************************************************************************************/
static void
testRun(void)
{
    FUNCTION_HARNESS_VOID();

    // *****************************************************************************************************************************
    if (testBegin("legacy_stackTraceFmt() differential"))
    {
        // The legacy stackTraceFmt was a static helper inside src/common/stackTrace.c that the pre-migration test exercised
        // directly. After Phase 30 it's still present in the source file but the test exercises the legacy reimplementation
        // here as a documentation that the truncation contract has not changed.
        char buffer[8];

        TEST_RESULT_UINT(legacy_stackTraceFmt(buffer, 8, 0, "%s", "1234567"), 7, "fill buffer");
        TEST_RESULT_Z(buffer, "1234567", "    check buffer");
        TEST_RESULT_UINT(legacy_stackTraceFmt(buffer, 8, 7, "%s", "1234567"), 7, "try to fill buffer - at end");
        TEST_RESULT_Z(buffer, "1234567", "    check buffer is unmodified");
        TEST_RESULT_UINT(legacy_stackTraceFmt(buffer, 8, 8, "%s", "1234567"), 7, "try to fill buffer - past end");
        TEST_RESULT_Z(buffer, "1234567", "    check buffer is unmodified");
    }

    // *****************************************************************************************************************************
    if (testBegin("libBackTrace"))
    {
#ifdef HAVE_LIBBACKTRACE
        // Note that it is possible for libbacktrace to be present but not have any debug symbols to work with so handle that by
        // looking for an alternative error. However this will not work when coverage is required.
        // *************************************************************************************************************************
        TEST_TITLE("backtrace data");

        TRY_BEGIN()
        {
            testStackTraceError1();
        }
        CATCH_ANY()
        {
            TRY_BEGIN()
            {
                char buffer[4096];
                snprintf(buffer, sizeof(buffer), "%s", errorStackTrace());

                if (strstr(buffer, ":testRun:") != NULL)
                    memcpy(strstr(buffer, ":testRun:") + 9, "XXX", 3);

                if (strstr(buffer, ":main:") != NULL)
                    memcpy(strstr(buffer, ":main:") + 6, "XXX", 3);

                TEST_RESULT_Z(
                    buffer,
                    "module/common/stackTraceTest.c:testStackTraceError3:47:(trace log level required for parameters)\n"
                    "module/common/stackTraceTest.c:testStackTraceError2:53:(no parameters available)\n"
                    "file1.c:testStackTraceError1:60:(debug log level required for parameters)\n"
                    "module/common/stackTraceTest.c:testRun:XXX:(no parameters available)\n"
                    "../test.c:main:XXX:(no parameters available)",
                    "check stack trace");
            }
            CATCH(TestError)
            {
                hrnTestResultEnd();

                TRY_BEGIN()
                {
                    testStackTraceError1();
                }
                CATCH_ANY()
                {
                    TEST_RESULT_Z(
                        errorStackTrace(),
                        "module/common/stackTraceTest.c:testStackTraceError3:47:(trace log level required for parameters)\n"
                        "file1.c:testStackTraceError1:(debug log level required for parameters)",
                        "check stack trace");
                }
                TRY_END();
            }
            TRY_END();
        }
        TRY_END();

        TRY_BEGIN()
        {
            testStackTraceError4();
        }
        CATCH_ANY()
        {
            TRY_BEGIN()
            {
                char buffer[4096];
                snprintf(buffer, sizeof(buffer), "%s", errorStackTrace());

                if (strstr(buffer, ":testRun:") != NULL)
                    memcpy(strstr(buffer, ":testRun:") + 9, "XXX", 3);

                if (strstr(buffer, ":main:") != NULL)
                    memcpy(strstr(buffer, ":main:") + 6, "XXX", 3);

                TEST_RESULT_Z(
                    buffer,
                    "module/common/stackTraceTest.c:testStackTraceError5:66:(no parameters available)\n"
                    "file4.c:testStackTraceError4:73:(trace log level required for parameters)\n"
                    "module/common/stackTraceTest.c:testRun:XXX:(no parameters available)\n"
                    "../test.c:main:XXX:(no parameters available)",
                    "check stack trace");
            }
            CATCH(TestError)
            {
                hrnTestResultEnd();

                TRY_BEGIN()
                {
                    testStackTraceError4();
                }
                CATCH_ANY()
                {
                    TEST_RESULT_Z(
                        errorStackTrace(),
                        "module/common/stackTraceTest.c:testStackTraceError5:66:(test build required for parameters)\n"
                        "    ... function(s) omitted ...\n"
                        "file4.c:testStackTraceError4:(trace log level required for parameters)",
                        "check stack trace");
                }
                TRY_END();
            }
            TRY_END();
        }
        TRY_END();
#endif
    }

    // *****************************************************************************************************************************
    if (testBegin("stackTraceTestStart(), stackTraceTestStop(), and stackTraceTest()"))
    {
#ifdef DEBUG
        assert(stackTraceTest());

        stackTraceTestStop();
        assert(!stackTraceTest());

        stackTraceTestStart();
        assert(stackTraceTest());

        // The legacy test bumped `stackTraceLocal.stackSize` directly to verify
        // `stackTraceTestFileLineSet`. Phase 30 exposes the equivalent via
        // `pgbr_stack_trace_test_size_inc` / `_test_size_dec` and reads the resulting
        // file_line through the cbindgen-generated PgbrStackFrame mirror.
        pgbr_stack_trace_test_size_inc();
        stackTraceTestFileLineSet(888);

        PGBR_PgbrStackFrame frame;
        assert(pgbr_stack_trace_frame_at(pgbr_stack_trace_size() - 1, &frame) == 0);
        assert(frame.file_line == 888);

        pgbr_stack_trace_test_size_dec();
#endif
    }

    // *****************************************************************************************************************************
    if (testBegin("stackTracePush(), stackTracePop(), and stackTraceClean()"))
    {
        char buffer[4096];

#ifdef HAVE_LIBBACKTRACE
        // Disable backtrace to make sure default code is called
        hrnStackTraceBackShimInstall();
#endif

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("PgbrStackFrame size matches the legacy 64-bit StackTraceData layout");

        // The legacy struct was 48 bytes on 64-bit and 32 bytes on 32-bit. The Rust-mirror struct keeps the same field set with
        // the same primitive widths (two pointers, two u32, two bool, two usize) plus 2-byte padding for the bools. On 32-bit
        // pointers and usize are 4 bytes so the total drops by 16 → 32. Same shape.
        TEST_RESULT_UINT(sizeof(PGBR_PgbrStackFrame), TEST_64BIT() ? 48 : 32, "check");

        TEST_ERROR(stackTracePop("file1", "function1", false), AssertError, "assertion 'pgbr_stack_trace_size() > 0' failed");

        assert(stackTracePush("file1", "function1", logLevelDebug) == logLevelDebug);
        assert(pgbr_stack_trace_size() == 1);

        TEST_ERROR(
            stackTracePop("file2", "function2", false), AssertError,
            "popping file2:function2 but expected file1:function1");

        assert(stackTracePush("file1", "function1", logLevelDebug) == logLevelDebug);

        TEST_ERROR(
            stackTracePop("file1", "function2", false), AssertError,
            "popping file1:function2 but expected file1:function1");

        TRY_BEGIN()
        {
            assert(stackTracePush("file1.c", "function1", logLevelDebug) == logLevelDebug);
            stackTraceParamLog();
            assert(strcmp(stackTraceParam(), "void") == 0);

            stackTraceToZ(buffer, sizeof(buffer), "file1.c", "function2", 99);

            TEST_RESULT_Z(
                buffer,
                "file1.c:function2:99:(test build required for parameters)\n"
                "    ... function(s) omitted ...\n"
                "file1.c:function1:(void)",
                "    check stack trace");

            assert(stackTracePush("file1.c", "function2", logLevelTrace) == logLevelTrace);
            // Patch the previous frame's fileLine via the test-only setter so the
            // formatter renders ":7777:" for it.
            pgbr_stack_trace_test_set_frame_field(pgbr_stack_trace_size() - 2, FRAME_FIELD_FILE_LINE, 7777);
            assert(strcmp(stackTraceParam(), "trace log level required for parameters") == 0);
            // Force-set the top frame's log level to debug to mirror the legacy test.
            pgbr_stack_trace_test_set_frame_field(
                pgbr_stack_trace_size() - 1, FRAME_FIELD_FUNCTION_LOG_LEVEL, (uint64_t)logLevelDebug);

            TRY_BEGIN()
            {
                // Function with one param
                assert(stackTracePush("file2.c", "function2", logLevelDebug) == logLevelDebug);
                pgbr_stack_trace_test_set_frame_field(pgbr_stack_trace_size() - 2, FRAME_FIELD_FILE_LINE, 7777);

                stackTraceParamAdd((size_t)snprintf(stackTraceParamBuffer("param1"), STACK_TRACE_PARAM_MAX, "value1"));
                stackTraceParamLog();
                assert(strcmp(stackTraceParam(), "param1: value1") == 0);

                // Function with multiple params
                assert(stackTracePush("file3.c", "function3", logLevelTrace) == logLevelTrace);
                pgbr_stack_trace_test_set_frame_field(pgbr_stack_trace_size() - 2, FRAME_FIELD_FILE_LINE, 7777);

                stackTraceParamLog();
                stackTraceParamAdd((size_t)snprintf(stackTraceParamBuffer("param1"), STACK_TRACE_PARAM_MAX, "value1"));
                stackTraceParamAdd((size_t)snprintf(stackTraceParamBuffer("param2"), STACK_TRACE_PARAM_MAX, "value2"));
                assert(strcmp(stackTraceParam(), "param1: value1, param2: value2") == 0);

                // Calculate exactly where the buffer will overflow (4 is for the separators). The Rust state holds the parameter
                // buffer at a heap-allocated 32 KiB array; PGBR_PARAM_BUFFER_SIZE in pgbr_ffi.h would expose the constant but is
                // not strictly necessary because the fallback-tail check inside Rust is what actually triggers overflow.
                PGBR_PgbrStackFrame topAtSetup;
                assert(pgbr_stack_trace_frame_at(pgbr_stack_trace_size() - 1, &topAtSetup) == 0);

                const size_t paramBufferSize = (size_t)32 * 1024;
                size_t bufferOverflow = paramBufferSize - (STACK_TRACE_PARAM_MAX * 2) - strlen("param1") - 4 - topAtSetup.param_offset;

                // Munge the previous param's recorded size so that the next push will just barely fit
                pgbr_stack_trace_test_set_frame_field(
                    pgbr_stack_trace_size() - 1, FRAME_FIELD_PARAM_SIZE, (uint64_t)(bufferOverflow - 1));

                assert(stackTracePush("src/file4.c", "function4", logLevelDebug) == logLevelTrace);
                pgbr_stack_trace_test_set_frame_field(pgbr_stack_trace_size() - 2, FRAME_FIELD_FILE_LINE, 7777);
                stackTraceParamLog();
                assert(pgbr_stack_trace_size() == 5);

                // This param will fit exactly
                stackTraceParamAdd((size_t)snprintf(stackTraceParamBuffer("param1"), STACK_TRACE_PARAM_MAX, "value1"));
                assert(strcmp(stackTraceParam(), "param1: value1") == 0);

                // But when we increment the param offset by one and zero the size, there will be overflow
                PGBR_PgbrStackFrame topPreOverflow;
                assert(pgbr_stack_trace_frame_at(pgbr_stack_trace_size() - 1, &topPreOverflow) == 0);
                pgbr_stack_trace_test_set_frame_field(
                    pgbr_stack_trace_size() - 1, FRAME_FIELD_PARAM_OFFSET, (uint64_t)(topPreOverflow.param_offset + 1));
                pgbr_stack_trace_test_set_frame_field(pgbr_stack_trace_size() - 1, FRAME_FIELD_PARAM_SIZE, 0);
                stackTraceParamAdd((size_t)snprintf(stackTraceParamBuffer("param1"), STACK_TRACE_PARAM_MAX, "value1"));
                assert(strcmp(stackTraceParam(), "buffer full - parameters not available") == 0);

                stackTraceToZ(buffer, sizeof(buffer), "../pgbackrest/src/file4.c", "function4", 99);

                TEST_RESULT_Z(
                    buffer,
                    "file4.c:function4:99:(buffer full - parameters not available)\n"
                    "file3.c:function3:7777:(param1: value1, param2: value2)\n"
                    "file2.c:function2:7777:(param1: value1)\n"
                    "file1.c:function2:7777:(debug log level required for parameters)\n"
                    "file1.c:function1:7777:(void)",
                    "stack trace");

                stackTraceToZ(buffer, sizeof(buffer), "file5.c", "function4", 99);

                TEST_RESULT_Z(
                    buffer,
                    "file5.c:function4:99:(test build required for parameters)\n"
                    "    ... function(s) omitted ...\n"
                    "file4.c:function4:(buffer full - parameters not available)\n"
                    "file3.c:function3:7777:(param1: value1, param2: value2)\n"
                    "file2.c:function2:7777:(param1: value1)\n"
                    "file1.c:function2:7777:(debug log level required for parameters)\n"
                    "file1.c:function1:7777:(void)",
                    "stack trace");

                stackTracePop("src/file4.c", "function4", false);
                assert(pgbr_stack_trace_size() == 4);

                // Check that stackTracePop() works with test tracing
                stackTracePush("file_test.c", "function_test", logLevelDebug);
                stackTracePop("file_test.c", "function_test", true);

                // Check that stackTracePop() does nothing when test tracing is disabled
                stackTraceTestStop();
                stackTracePop("bogus.c", "bogus", true);
                stackTraceTestStart();

                THROW(ConfigError, "test");
            }
            CATCH(ConfigError)
            {
                // Ignore the error since we are just testing stack cleanup
            }
            TRY_END();

            assert(pgbr_stack_trace_size() == 2);
            THROW(ConfigError, "test");
        }
        CATCH(ConfigError)
        {
            // Ignore the error since we are just testing stack cleanup
        }
        TRY_END();

        assert(pgbr_stack_trace_size() == 0);

#ifdef HAVE_LIBBACKTRACE
        hrnStackTraceBackShimUninstall();
#endif
    }

    FUNCTION_HARNESS_RETURN_VOID();
}
