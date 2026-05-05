/***********************************************************************************************************************************
Stack Trace Handler

Thin C wrappers over the Rust accumulator in `crates/pgbr-core::stack_trace`. The frame stack, parameter buffer, test flag and the
"force-no-backtrace" override all live in Rust; the public API in `src/common/stackTrace.h` is preserved byte-for-byte.

The libbacktrace integration stays here because `backtrace_full` takes a C function-pointer callback and reads platform-specific
debug data (`backtrace_create_state`). The callback resolves frames the linker enumerated and matches them against the Rust state
through the `pgbr_stack_trace_*` FFI getters; the fallback formatter (when libbacktrace returns no frames) walks the same Rust
state directly.
***********************************************************************************************************************************/
#include <build.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_LIBBACKTRACE
    #include <backtrace.h>
#endif

#include "common/assert.h"
#include "common/macro.h"
#include "common/stackTrace.h"
#include "pgbr_ffi.h"

#ifdef HAVE_LIBBACKTRACE
// libbacktrace state — single-instance, lazily created on first use. Stays on the C side because the libbacktrace API talks in C
// pointers and is platform-specific.
static struct backtrace_state *backTraceState;
#endif

/**********************************************************************************************************************************/
#ifdef DEBUG

FN_EXTERN void
stackTraceTestStart(void)
{
    pgbr_stack_trace_test_start();
}

FN_EXTERN void
stackTraceTestStop(void)
{
    pgbr_stack_trace_test_stop();
}

FN_EXTERN bool
stackTraceTest(void)
{
    return pgbr_stack_trace_test_flag();
}

FN_EXTERN void
stackTraceTestFileLineSet(unsigned int fileLine)
{
    pgbr_stack_trace_test_file_line_set((uint32_t)fileLine);
}

#endif

/**********************************************************************************************************************************/
FN_EXTERN LogLevel
stackTracePush(const char *const fileName, const char *const functionName, const LogLevel functionLogLevel)
{
    // The Rust side asserts on overflow with `panic!`, which crosses the FFI boundary as an `Unknown` error. Mirror the legacy
    // C `ASSERT(stackTraceLocal.stackSize < STACK_TRACE_MAX - 1)` here so the throw shows up as an AssertError with the same
    // diagnostic shape the existing test expects.
    ASSERT(pgbr_stack_trace_size() < 127);

    return (LogLevel)pgbr_stack_trace_push(fileName, functionName, (int32_t)functionLogLevel, errorTryDepth());
}

/**********************************************************************************************************************************/
FN_EXTERN const char *
stackTraceParam(void)
{
    return pgbr_stack_trace_param_top();
}

/**********************************************************************************************************************************/
FN_EXTERN char *
stackTraceParamBuffer(const char *const paramName)
{
    return pgbr_stack_trace_param_buffer(paramName);
}

/**********************************************************************************************************************************/
FN_EXTERN void
stackTraceParamAdd(const size_t bufferSize)
{
    pgbr_stack_trace_param_add(bufferSize);
}

/**********************************************************************************************************************************/
FN_EXTERN void
stackTraceParamLog(void)
{
    pgbr_stack_trace_param_log();
}

/**********************************************************************************************************************************/
#ifdef DEBUG

FN_EXTERN void
stackTracePop(const char *const fileName, const char *const functionName, const bool test)
{
    // Mirror the legacy `ASSERT(stackTraceLocal.stackSize > 0)` so underflow throws AssertError before reaching Rust.
    ASSERT(pgbr_stack_trace_size() > 0);

    if (pgbr_stack_trace_pop_debug(fileName, functionName, test) != 0)
    {
        // The Rust side records the diagnostic message in the thread-local last-error slot; re-throw via the standard bridge so
        // the caller sees an AssertError with the correct file/function/line.
        pgbr_error_throw_from_last(__FILE__, __func__, __LINE__);
    }
}

#else

FN_EXTERN void
stackTracePop(void)
{
    ASSERT(pgbr_stack_trace_size() > 0);
    pgbr_stack_trace_pop_release();
}

#endif

/***********************************************************************************************************************************
Stack trace format helper. Kept on the C side because it consumes a variadic format string via `vsnprintf`; the legacy test
exercises it directly and keeping it here avoids marshalling the variadic args across the FFI boundary.
***********************************************************************************************************************************/
static FN_PRINTF(4, 5) size_t
stackTraceFmt(char *const buffer, const size_t bufferSize, const size_t bufferUsed, const char *const format, ...)
{
    va_list argumentList;
    va_start(argumentList, format);
    const int result = vsnprintf(
        buffer + bufferUsed, bufferUsed < bufferSize ? bufferSize - bufferUsed : 0, format, argumentList);
    va_end(argumentList);

    return (size_t)result;
}

/***********************************************************************************************************************************
Helper to trim off extra path before the src path. Mirrors `pgbr_core::stack_trace::trim_src` byte-for-byte; kept here so the
libbacktrace callback does not have to allocate to call into Rust.
***********************************************************************************************************************************/
static const char *
stackTraceTrimSrc(const char *const fileName)
{
    const char *const src = strstr(fileName, "src/");
    return src == NULL ? fileName : src + 4;
}

/**********************************************************************************************************************************/
#ifdef HAVE_LIBBACKTRACE

typedef struct StackTraceBackData
{
    bool firstCall;
    bool firstLine;
    int stackIdx;
    size_t result;
    char *const buffer;
    const size_t bufferSize;
} StackTraceBackData;

// Callback to add backtrace data when available
static int
stackTraceBackCallback(
    void *const dataVoid, const uintptr_t pc, const char *fileName, const int fileLine, const char *const functionName)
{
    (void)pc;
    StackTraceBackData *const data = dataVoid;

    // Catch any unset parameters which indicates the debug data is not available
    if (fileName == NULL || fileLine == 0 || functionName == NULL)
    {
        // If this is the first call then stop because the top of the backtrace must be one of our functions
        if (data->firstCall)
            return true;

        // Else return but do not stop
        data->firstCall = false;
        return false;
    }

    // Reset first call
    data->firstCall = false;

    // If the function name matches combine backtrace data with stack data
    PGBR_PgbrStackFrame frame;
    bool matched = false;

    if (data->stackIdx >= 0 && pgbr_stack_trace_frame_at((size_t)data->stackIdx, &frame) == 0 &&
        strcmp(functionName, frame.function_name) == 0)
    {
        data->result += stackTraceFmt(
            data->buffer, data->bufferSize, data->result, "%s%s:%s:%d:(%s)", data->firstLine ? "" : "\n",
            stackTraceTrimSrc(frame.file_name), functionName, fileLine, pgbr_stack_trace_param_idx((size_t)data->stackIdx));

        data->stackIdx--;
        matched = true;
    }

    if (!matched)
    {
        fileName = stackTraceTrimSrc(fileName);

        // Else just use stack data. Skip any functions in the error module since they are not useful for the user
        if (strcmp(fileName, "common/error/error.c") == 0)
            return false;

        data->result += stackTraceFmt(
            data->buffer, data->bufferSize, data->result, "%s%s:%s:%d:(no parameters available)", data->firstLine ? "" : "\n",
            fileName, functionName, fileLine);
    }

    // Reset first line
    data->firstLine = false;

    // Stop when the main function has been processed
    return strcmp(functionName, "main") == 0;
}

// Dummy error callback. If there is an error just generate the default stack trace.
static void
stackTraceBackErrorCallback(void *const data, const char *const msg, const int errnum)
{
    (void)data;
    (void)msg;
    (void)errnum;
}

#endif

FN_EXTERN size_t
stackTraceToZ(
    char *const buffer, const size_t bufferSize, const char *fileName, const char *const functionName,
    const unsigned int fileLine)
{
#ifdef HAVE_LIBBACKTRACE
    if (!pgbr_stack_trace_force_no_backtrace_get())
    {
        StackTraceBackData data =
        {
            .firstCall = true,
            .firstLine = true,
            .stackIdx = (int)pgbr_stack_trace_size() - 1,
            .result = 0,
            .buffer = buffer,
            .bufferSize = bufferSize,
        };

        if (backTraceState == NULL)
            backTraceState = backtrace_create_state(NULL, false, NULL, NULL);

        backtrace_full(backTraceState, 2, stackTraceBackCallback, stackTraceBackErrorCallback, &data);

        if (data.result != 0)
            return data.result;
    }
#endif // HAVE_LIBBACKTRACE

    size_t result = 0;
    const char *param = "test build required for parameters";
    const size_t stackSize = pgbr_stack_trace_size();
    int stackIdx = (int)stackSize - 1;

    // If the current function passed in is the same as the top function on the stack then use the parameters for that function
    fileName = stackTraceTrimSrc(fileName);

    PGBR_PgbrStackFrame topFrame;

    if (stackSize > 0 && pgbr_stack_trace_frame_at((size_t)stackIdx, &topFrame) == 0 &&
        strcmp(fileName, stackTraceTrimSrc(topFrame.file_name)) == 0 &&
        strcmp(functionName, topFrame.function_name) == 0)
    {
        param = pgbr_stack_trace_param_idx((size_t)stackIdx);
        stackIdx--;
    }

    // Output the current function
    result = stackTraceFmt(buffer, bufferSize, 0, "%s:%s:%u:(%s)", fileName, functionName, fileLine, param);

    // Output stack if there is anything on it
    if (stackIdx >= 0)
    {
        // If the function passed in was not at the top of the stack then some functions are missing
        if (stackIdx == (int)stackSize - 1)
            result += stackTraceFmt(buffer, bufferSize, result, "\n    ... function(s) omitted ...");

        // Output the rest of the stack
        for (; stackIdx >= 0; stackIdx--)
        {
            PGBR_PgbrStackFrame frame;
            if (pgbr_stack_trace_frame_at((size_t)stackIdx, &frame) != 0)
                break;

            result += stackTraceFmt(buffer, bufferSize, result, "\n%s:%s", stackTraceTrimSrc(frame.file_name), frame.function_name);

            if (frame.file_line > 0)
                result += stackTraceFmt(buffer, bufferSize, result, ":%u", frame.file_line);

            result += stackTraceFmt(buffer, bufferSize, result, ":(%s)", pgbr_stack_trace_param_idx((size_t)stackIdx));
        }
    }

    return result;
}

/**********************************************************************************************************************************/
FN_EXTERN void
stackTraceClean(const unsigned int tryDepth, const bool fatal)
{
    (void)fatal;                                                    // Cleanup is the same for fatal errors
    pgbr_stack_trace_clean((uint32_t)tryDepth);
}
