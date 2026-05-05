/***********************************************************************************************************************************
Error Handler

Phase 27 of the C->Rust migration is split across three sub-issues — see #222, #223, #224 — because the full body of this file
cannot be replaced with thin Rust FFI shims while the C `setjmp`/`longjmp` state machine and the frozen `const ErrorType *` ABI
are in place. What lives where after the split:

  pgbr-error (Rust crate, called via pgbr-ffi)
    - ErrorType enum + lookups (parent / extends / from_code / from_name / is_fatal). Sub-issue #222.
    - Printf-style message formatting (`pgbr_error::format::format_message`), reached from the Throw_Fmt
      family below via `pgbr_error_format_message` and the args-blob marshalling in `errorMarshalArgs`. Sub-issue #223.
    - `Error::throw_into_c` helper for Rust callers that already have an `Error` in hand. Sub-issue #224.

  This file (C — stays here for the foreseeable future)
    - The TRY / CATCH / FINALLY state machine (`errorInternalTryBegin`, `errorInternalCatch`,
      `errorInternalPropagate`, `errorInternalTryEnd`) and the `jumpList` of `jmp_buf` slots.
    - The Throw_Fmt family that callers reach through THROW_FMT macros — bodies retained because they accept
      C varargs and longjmp out of the call site, neither of which Rust can do safely.
    - `pgbr_error_throw_from_last`, the canonical exit point for Rust shims that need to longjmp into the
      nearest TRY block via the same machinery as `THROW_FMT`.

The C source above will be removed in bulk at Phase 212 alongside the rest of the legacy C tree, at which point the public
ErrorType API is replaced by a Rust-native equivalent. Until then this file is a thin set of wrappers around the Rust formatter
plus the C-only TRY state machine.
***********************************************************************************************************************************/
#include <build.h>

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/error/error.h"
#include "common/macro.h"
#include "common/stackTrace.h"
#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Represents an error type
***********************************************************************************************************************************/
struct ErrorType
{
    const int code;
    const bool fatal;
    const char *name;
    const struct ErrorType *parentType;
};

// Macro for defining new error types
#define ERROR_DEFINE(code, name, fatal, parentType)                                                                                \
    VR_EXTERN_DEFINE const ErrorType name = {code, fatal, #name, &parentType}

// Define test error
#ifdef DEBUG
ERROR_DEFINE(1, TestError, false, RuntimeError);
#endif

// Include error type definitions
#include "common/error/error.auto.c.inc"

/***********************************************************************************************************************************
Maximum allowed number of nested try blocks
***********************************************************************************************************************************/
#define ERROR_TRY_MAX                                             64

/***********************************************************************************************************************************
States for each try
***********************************************************************************************************************************/
typedef enum {errorStateTry, errorStateCatch, errorStateEnd} ErrorState;

/***********************************************************************************************************************************
Track error handling
***********************************************************************************************************************************/
typedef struct Error
{
    const ErrorType *errorType;                                     // Error type
    const char *fileName;                                           // Source file where the error occurred
    const char *functionName;                                       // Function where the error occurred
    int fileLine;                                                   // Source file line where the error occurred
    const char *message;                                            // Description of the error
    const char *stackTrace;                                         // Stack trace
} Error;

static struct
{
    // Array of jump buffers
    jmp_buf jumpList[ERROR_TRY_MAX];

    // Handler list
    const ErrorHandlerFunction *handlerList;
    unsigned int handlerTotal;

    // State of each try
    int tryTotal;

    struct
    {
        ErrorState state;
        bool uncaught;
    } tryList[ERROR_TRY_MAX + 1];

    // Last error
    Error error;
} errorContext;

/***********************************************************************************************************************************
Message buffer and buffer size

The message buffer is statically allocated so there is some space to store error messages. Not being able to allocate such a small
amount of memory seems pretty unlikely so just keep the code simple and let the loader deal with massively constrained memory
situations.

The temp buffer is required because the error message being passed might be the error already stored in the message buffer.
***********************************************************************************************************************************/
#ifndef ERROR_MESSAGE_BUFFER_SIZE
#define ERROR_MESSAGE_BUFFER_SIZE                                   8192
#endif

static char messageBuffer[ERROR_MESSAGE_BUFFER_SIZE];
static char messageBufferTemp[ERROR_MESSAGE_BUFFER_SIZE];
static char stackTraceBuffer[ERROR_MESSAGE_BUFFER_SIZE];

/***********************************************************************************************************************************
Format-string marshalling for the Rust-side message formatter

Walks `format` once, reading each `va_arg` according to the spec, and packs the typed values into `out` in declaration order. The
spec parser must accept exactly the conversion specifiers the Rust formatter understands (see crates/pgbr-error/src/format.rs):
%s %c %d %i %u %X %% with optional `0` flag, decimal width, `.precision`, and `z` / `l` / `ll` length modifiers. Any unknown
specifier is skipped without consuming an arg, and the Rust side will surface it as a programmer error.

Returns the number of args written into `out`. Asserts on overflow rather than silently dropping arguments — every current
THROW_FMT call site uses well under ERROR_FMT_ARG_MAX entries, so an overflow indicates a bug.
***********************************************************************************************************************************/
#define ERROR_FMT_ARG_MAX                                           16

static unsigned int
errorMarshalArgs(const char *format, va_list args, PGBR_PgbrFmtArg *const out)
{
    unsigned int n = 0;
    const char *p = format;

    while (*p != '\0')
    {
        if (*p != '%')
        {
            p++;
            continue;
        }

        p++;                                                        // consume '%'

        // Flag: only '0' is used by pgBackRust call sites.
        if (*p == '0')
            p++;

        // Width digits.
        while (*p >= '0' && *p <= '9')
            p++;

        // Precision.
        if (*p == '.')
        {
            p++;

            while (*p >= '0' && *p <= '9')
                p++;
        }

        // Length modifier.
        char lenMod = 0;

        if (*p == 'z')
        {
            lenMod = 'z';
            p++;
        }
        else if (*p == 'l')
        {
            lenMod = 'l';
            p++;

            if (*p == 'l')
            {
                lenMod = 'L';
                p++;
            }
        }

        // Conversion specifier.
        const char conv = *p;

        if (conv == '\0')
            break;

        p++;

        if (conv == '%')
            continue;                                               // %% does not consume an arg

        assert(n < ERROR_FMT_ARG_MAX);
        PGBR_PgbrFmtArg *const arg = &out[n];

        // Zero the slot first so unused payload bytes are deterministic on the Rust side.
        arg->kind = 0;
        arg->reserved = 0;
        arg->value_a = 0;
        arg->value_b = 0;

        switch (conv)
        {
            case 's':
            {
                const char *const s = va_arg(args, const char *);

                arg->kind = 7;                                      // PgbrFmtArgKind::Str
                arg->value_a = (uint64_t)(uintptr_t)(s == NULL ? "" : s);
                arg->value_b = (uint64_t)(s == NULL ? 0 : strlen(s));
                break;
            }

            case 'c':
                arg->kind = 6;                                      // PgbrFmtArgKind::Char
                arg->value_a = (uint64_t)(unsigned char)va_arg(args, int);
                break;

            case 'd':
            case 'i':
                if (lenMod == 'z')
                {
                    arg->kind = 4;                                  // PgbrFmtArgKind::Isize
                    arg->value_a = (uint64_t)(int64_t)va_arg(args, ssize_t);
                }
                else if (lenMod == 'l' || lenMod == 'L')
                {
                    arg->kind = 2;                                  // PgbrFmtArgKind::I64
                    arg->value_a = (uint64_t)(int64_t)va_arg(args, long);
                }
                else
                {
                    arg->kind = 0;                                  // PgbrFmtArgKind::I32
                    arg->value_a = (uint64_t)(uint32_t)va_arg(args, int);
                }

                break;

            case 'u':
            case 'x':
            case 'X':
                if (lenMod == 'z')
                {
                    arg->kind = 5;                                  // PgbrFmtArgKind::Usize
                    arg->value_a = (uint64_t)va_arg(args, size_t);
                }
                else if (lenMod == 'l' || lenMod == 'L')
                {
                    arg->kind = 3;                                  // PgbrFmtArgKind::U64
                    arg->value_a = (uint64_t)va_arg(args, unsigned long);
                }
                else
                {
                    arg->kind = 1;                                  // PgbrFmtArgKind::U32
                    arg->value_a = (uint64_t)va_arg(args, unsigned int);
                }

                break;

            default:
                // Unknown specifier — the Rust side will emit it literally and a debug build
                // will assert. Don't consume an arg here; leave the slot unused.
                continue;
        }

        n++;
    }

    return n;
}

/**********************************************************************************************************************************/
FN_EXTERN void
errorHandlerSet(const ErrorHandlerFunction *const list, const unsigned int total)
{
    assert(total == 0 || list != NULL);

    errorContext.handlerList = list;
    errorContext.handlerTotal = total;
}

/**********************************************************************************************************************************/
FN_EXTERN int
errorTypeCode(const ErrorType *const errorType)
{
    return errorType->code;
}

/**********************************************************************************************************************************/
FN_EXTERN bool
errorTypeFatal(const ErrorType *const errorType)
{
    return errorType->fatal;
}

/**********************************************************************************************************************************/
FN_EXTERN const ErrorType *
errorTypeFromCode(const int code)
{
    // Search for error type by code
    int errorTypeIdx = 0;
    const ErrorType *result = errorTypeList[errorTypeIdx];

    while (result != NULL)
    {
        if (result->code == code)
            break;

        result = errorTypeList[++errorTypeIdx];
    }

    // Error if type was not found
    if (result == NULL)
        result = &UnknownError;

    return result;
}

/**********************************************************************************************************************************/
FN_EXTERN const char *
errorTypeName(const ErrorType *const errorType)
{
    return errorType->name;
}

/**********************************************************************************************************************************/
FN_EXTERN const ErrorType *
errorTypeParent(const ErrorType *const errorType)
{
    return errorType->parentType;
}

/**********************************************************************************************************************************/
FN_EXTERN unsigned int
errorTryDepth(void)
{
    return (unsigned int)errorContext.tryTotal;
}

/**********************************************************************************************************************************/
FN_EXTERN void
pgbr_error_throw_from_last(const char *const fileName, const char *const functionName, const int fileLine)
{
    const int code = pgbr_last_error_code();

    // Caller must populate the slot first via pgbr_last_error_set or set_last_error in Rust. Surfacing this as an AssertError
    // (rather than silently returning) makes the misuse visible and reuses the existing exception machinery.
    if (code == 0)
    {
        errorInternalThrowFmt(
            &AssertError, fileName, functionName, fileLine,
            "pgbr_error_throw_from_last called with no last error set");
    }

    const ErrorType *const type = errorTypeFromCode(code);
    const char *const message = pgbr_last_error_msg();

    // Snapshot the message into a temp buffer before clearing the Rust-side slot. The buffer the message points into is owned
    // by Rust's thread-local; clearing the slot invalidates it, and `errorInternalThrowFmt` itself writes through
    // `messageBufferTemp` which could in principle alias.
    char messageCopy[ERROR_MESSAGE_BUFFER_SIZE];

    if (message == NULL)
    {
        messageCopy[0] = '\0';
    }
    else
    {
        strncpy(messageCopy, message, sizeof(messageCopy));
        messageCopy[sizeof(messageCopy) - 1] = '\0';
    }

    pgbr_last_error_clear();

    errorInternalThrowFmt(type, fileName, functionName, fileLine, "%s", messageCopy);
}

/**********************************************************************************************************************************/
FN_EXTERN bool
errorTypeExtends(const ErrorType *const child, const ErrorType *const parent)
{
    const ErrorType *find = child;

    do
    {
        find = errorTypeParent(find);

        // Parent was found
        if (find == parent)
            return true;
    }
    while (find != errorTypeParent(find));

    // Parent was not found
    return false;
}

/**********************************************************************************************************************************/
FN_EXTERN const ErrorType *
errorType(void)
{
    assert(errorContext.error.errorType != NULL);

    return errorContext.error.errorType;
}

/**********************************************************************************************************************************/
FN_EXTERN int
errorCode(void)
{
    return errorTypeCode(errorType());
}

/**********************************************************************************************************************************/
FN_EXTERN bool
errorFatal(void)
{
    return errorTypeFatal(errorType());
}

/**********************************************************************************************************************************/
FN_EXTERN const char *
errorFileName(void)
{
    assert(errorContext.error.fileName != NULL);

    return errorContext.error.fileName;
}

/**********************************************************************************************************************************/
FN_EXTERN const char *
errorFunctionName(void)
{
    assert(errorContext.error.functionName != NULL);

    return errorContext.error.functionName;
}

/**********************************************************************************************************************************/
FN_EXTERN int
errorFileLine(void)
{
    assert(errorContext.error.fileLine != 0);

    return errorContext.error.fileLine;
}

/**********************************************************************************************************************************/
FN_EXTERN const char *
errorMessage(void)
{
    assert(errorContext.error.message != NULL);

    return errorContext.error.message;
}

/**********************************************************************************************************************************/
FN_EXTERN const char *
errorName(void)
{
    return errorTypeName(errorType());
}

/**********************************************************************************************************************************/
FN_EXTERN const char *
errorStackTrace(void)
{
    assert(errorContext.error.stackTrace != NULL);

    return errorContext.error.stackTrace;
}

/**********************************************************************************************************************************/
FN_EXTERN bool
errorInstanceOf(const ErrorType *const errorTypeTest)
{
    return errorType() == errorTypeTest || errorTypeExtends(errorType(), errorTypeTest);
}

/***********************************************************************************************************************************
Return current error context state
***********************************************************************************************************************************/
static ErrorState
errorInternalState(void)
{
    return errorContext.tryList[errorContext.tryTotal].state;
}

/**********************************************************************************************************************************/
FN_EXTERN void
errorInternalTryBegin(const char *const fileName, const char *const functionName, const int fileLine)
{
    // If try total has been exceeded then throw an error
    if (errorContext.tryTotal >= ERROR_TRY_MAX)
        errorInternalThrowFmt(&AssertError, fileName, functionName, fileLine, "too many nested try blocks");

    // Increment try total
    errorContext.tryTotal++;

    // Setup try
    errorContext.tryList[errorContext.tryTotal].state = errorStateTry;
    errorContext.tryList[errorContext.tryTotal].uncaught = false;
}

/**********************************************************************************************************************************/
FN_EXTERN jmp_buf *
errorInternalJump(void)
{
    return &errorContext.jumpList[errorContext.tryTotal - 1];
}

/**********************************************************************************************************************************/
FN_EXTERN bool
errorInternalCatch(const ErrorType *const errorTypeCatch, const bool fatalCatch)
{
    assert(fatalCatch || !errorTypeFatal(errorTypeCatch));

    // If just entering error state clean up the stack
    if (errorInternalState() == errorStateTry)
    {
        for (unsigned int handlerIdx = 0; handlerIdx < errorContext.handlerTotal; handlerIdx++)
            errorContext.handlerList[handlerIdx](errorTryDepth(), fatalCatch);

        errorContext.tryList[errorContext.tryTotal].state++;
    }

    if (errorInternalState() == errorStateCatch && errorInstanceOf(errorTypeCatch) && (fatalCatch || !errorFatal()))
    {
        errorContext.tryList[errorContext.tryTotal].uncaught = false;
        errorContext.tryList[errorContext.tryTotal].state++;

        return true;
    }

    return false;
}

/**********************************************************************************************************************************/
FN_EXTERN void
errorInternalPropagate(void)
{
    assert(errorType() != NULL);

    // Mark the error as uncaught
    errorContext.tryList[errorContext.tryTotal].uncaught = true;

    // If there is a parent try then jump to it
    if (errorContext.tryTotal > 0)
        longjmp(errorContext.jumpList[errorContext.tryTotal - 1], 1);

    // If there was no try to catch this error then output to stderr
    fprintf(stderr, "\nUncaught %s: %s\n    thrown at %s:%d\n\n", errorName(), errorMessage(), errorFileName(), errorFileLine());
    fflush(stderr);

    // Exit with failure
    exit(UnhandledError.code);
}

/**********************************************************************************************************************************/
FN_EXTERN void
errorInternalTryEnd(void)
{
    // Any catch blocks have been processed and none of them called RETHROW() so clear the error
    if (errorInternalState() == errorStateEnd && !errorContext.tryList[errorContext.tryTotal].uncaught)
        errorContext.error = (Error){0};

    // Remove the try
    errorContext.tryTotal--;

    // If not caught in the last try then propagate
    if (errorContext.tryList[errorContext.tryTotal + 1].uncaught)
        errorInternalPropagate();
}

/**********************************************************************************************************************************/
FN_EXTERN void
errorInternalThrow(
    const ErrorType *const errorType, const char *const fileName, const char *const functionName, const int fileLine,
    const char *const message, const char *const stackTrace)
{
    // Setup error data
    errorContext.error.errorType = errorType;
    errorContext.error.fileName = fileName;
    errorContext.error.functionName = functionName;
    errorContext.error.fileLine = fileLine;

    // Assign message to the error. If errorMessage() is passed as the message there is no need to make a copy.
    if (message != messageBuffer)
    {
        strncpy(messageBuffer, message, sizeof(messageBuffer));
        messageBuffer[sizeof(messageBuffer) - 1] = 0;
    }

    errorContext.error.message = (const char *)messageBuffer;

    // If a stack trace was provided
    if (stackTrace != NULL)
    {
        strncpy(stackTraceBuffer, stackTrace, sizeof(stackTraceBuffer) - 1);
        messageBuffer[sizeof(stackTraceBuffer) - 1] = '\0';
    }
    // Else generate the stack trace for the error
    else if (
        stackTraceToZ(
            stackTraceBuffer, sizeof(stackTraceBuffer), errorFileName(), errorFunctionName(),
            (unsigned int)fileLine) >= sizeof(stackTraceBuffer))
    {
        // Indicate that the stack trace was truncated
    }

    errorContext.error.stackTrace = (const char *)stackTraceBuffer;

    // Propagate the error
    errorInternalPropagate();
}

FN_EXTERN void
errorInternalThrowFmt(
    const ErrorType *const errorType, const char *const fileName, const char *const functionName, const int fileLine,
    const char *const format, ...)
{
    // Marshal varargs into a typed blob and format on the Rust side.
    PGBR_PgbrFmtArg fmtArgs[ERROR_FMT_ARG_MAX];
    va_list argument;
    va_start(argument, format);
    const unsigned int nArgs = errorMarshalArgs(format, argument, fmtArgs);
    va_end(argument);

    pgbr_error_format_message(format, fmtArgs, nArgs, messageBufferTemp, ERROR_MESSAGE_BUFFER_SIZE);

    errorInternalThrow(errorType, fileName, functionName, fileLine, messageBufferTemp, NULL);
}

/**********************************************************************************************************************************/
FN_EXTERN void
errorInternalThrowSys(
    const int errNo, const ErrorType *const errorType, const char *const fileName, const char *const functionName,
    const int fileLine, const char *const message)
{
    // Format message with system message appended
    if (errNo == 0)
    {
        strncpy(messageBufferTemp, message, ERROR_MESSAGE_BUFFER_SIZE - 1);
        messageBufferTemp[sizeof(messageBuffer) - 1] = 0;
    }
    else
        snprintf(messageBufferTemp, ERROR_MESSAGE_BUFFER_SIZE - 1, "%s: [%d] %s", message, errNo, strerror(errNo));

    errorInternalThrow(errorType, fileName, functionName, fileLine, messageBufferTemp, NULL);
}

#ifdef DEBUG_COVERAGE

FN_EXTERN void
errorInternalThrowOnSys(
    const bool error, const int errNo, const ErrorType *const errorType, const char *const fileName, const char *const functionName,
    const int fileLine, const char *const message)
{
    if (error)
        errorInternalThrowSys(errNo, errorType, fileName, functionName, fileLine, message);
}

#endif

FN_EXTERN void
errorInternalThrowSysFmt(
    const int errNo, const ErrorType *const errorType, const char *const fileName, const char *const functionName,
    const int fileLine, const char *const format, ...)
{
    // Marshal varargs and format the user message on the Rust side.
    PGBR_PgbrFmtArg fmtArgs[ERROR_FMT_ARG_MAX];
    va_list argument;
    va_start(argument, format);
    const unsigned int nArgs = errorMarshalArgs(format, argument, fmtArgs);
    va_end(argument);

    const size_t messageSize = pgbr_error_format_message(
        format, fmtArgs, nArgs, messageBufferTemp, ERROR_MESSAGE_BUFFER_SIZE);

    // Append the system message
    if (errNo != 0)
    {
        snprintf(
            messageBufferTemp + messageSize, ERROR_MESSAGE_BUFFER_SIZE - messageSize, ": [%d] %s", errNo, strerror(errNo));
    }

    errorInternalThrow(errorType, fileName, functionName, fileLine, messageBufferTemp, NULL);
}

#ifdef DEBUG_COVERAGE

FN_EXTERN void
errorInternalThrowOnSysFmt(
    const bool error, const int errNo, const ErrorType *const errorType, const char *const fileName, const char *const functionName,
    const int fileLine, const char *const format, ...)
{
    if (error)
    {
        // Marshal varargs and format the user message on the Rust side.
        PGBR_PgbrFmtArg fmtArgs[ERROR_FMT_ARG_MAX];
        va_list argument;
        va_start(argument, format);
        const unsigned int nArgs = errorMarshalArgs(format, argument, fmtArgs);
        va_end(argument);

        const size_t messageSize = pgbr_error_format_message(
            format, fmtArgs, nArgs, messageBufferTemp, ERROR_MESSAGE_BUFFER_SIZE);

        // Append the system message
        if (errNo != 0)
        {
            snprintf(
                messageBufferTemp + messageSize, ERROR_MESSAGE_BUFFER_SIZE - messageSize, ": [%d] %s", errNo, strerror(errNo));
        }

        errorInternalThrow(errorType, fileName, functionName, fileLine, messageBufferTemp, NULL);
    }
}

#endif
