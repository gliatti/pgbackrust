/***********************************************************************************************************************************
Error Retry Message

Thin C wrappers over the Rust implementation in `crates/pgbr-error::retry`. The accumulator state — first error, deduplicated retry
items, baseline timestamp — lives entirely in a `RetryState` owned by the Rust side; this file only manages the surrounding
`ErrorRetry` object lifetime and the conversion between the C public API (`String *`, `ErrorType *`, `TimeMSec`) and the FFI calls
in `pgbr_ffi.h`.

The `ErrorRetry` struct keeps its `pub.type` field (read by `errRetryType`, declared inline in `retry.h`) and the opaque Rust state
pointer; nothing else is needed at the C layer. The harness in `test/src/common/harnessErrorRetry.c` reaches into `this->state`
through the same FFI symbols and is intentionally co-evolved with this file.
***********************************************************************************************************************************/
#include <build.h>

#include "common/debug.h"
#include "common/error/retry.h"
#include "common/time.h"
#include "common/type/string.h"
#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Object type
***********************************************************************************************************************************/
struct ErrorRetry
{
    ErrorRetryPub pub;                                              // Publicly accessible variables (only `.type` today)
    void *state;                                                    // Opaque pointer to the Rust `RetryState`
};

/***********************************************************************************************************************************
Free the Rust-side state when the surrounding memory context is destroyed
***********************************************************************************************************************************/
static void
errRetryFreeResource(THIS_VOID)
{
    THIS(ErrorRetry);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ERROR_RETRY, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    pgbr_error_retry_state_free(this->state);
    this->state = NULL;

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN ErrorRetry *
errRetryNew(void)
{
    FUNCTION_TEST_VOID();

    OBJ_NEW_BEGIN(ErrorRetry, .childQty = MEM_CONTEXT_QTY_MAX, .callbackQty = 1)
    {
        *this = (ErrorRetry){.state = pgbr_error_retry_state_new((uint64_t)timeMSec())};

        // Set free callback so the Rust state is dropped when the memory context goes away.
        memContextCallbackSet(objMemContext(this), errRetryFreeResource, this);
    }
    OBJ_NEW_END();

    FUNCTION_TEST_RETURN(ERROR_RETRY, this);
}

/**********************************************************************************************************************************/
FN_EXTERN String *
errRetryMessage(const ErrorRetry *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ERROR_RETRY, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    // The Rust formatter returns NULL only when no first error has been recorded; the legacy code asserted on a NULL first message
    // at the same point, so callers are required to invoke at least one `errRetryAdd` first.
    const char *const message = pgbr_error_retry_state_format_message(this->state);
    ASSERT(message != NULL);

    FUNCTION_TEST_RETURN(STRING, strNewZ(message));
}

/**********************************************************************************************************************************/
FN_EXTERN void
errRetryAdd(ErrorRetry *const this, const ErrRetryAddParam param)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(ERROR_RETRY, this);
        FUNCTION_TEST_PARAM(ERROR_TYPE, param.type);
        FUNCTION_TEST_PARAM(STRING, param.message);
    FUNCTION_TEST_END();

    // Set defaults — same fallback semantics as the legacy implementation.
    const ErrorType *const type = param.type == NULL ? errorType() : param.type;
    const char *const message = param.message == NULL ? errorMessage() : strZ(param.message);

    // Match the legacy clock-consumption pattern: the first error path does not read `timeMSec()` (the Rust state ignores `now_ms`
    // on its first add), so we pass `0` as a stable sentinel and only fetch a real timestamp on later retries. Tests that drive
    // the harness via `hrnTimeMSecSet` rely on this — without it, the first add would consume one fixture more than the legacy C
    // path and every retry timestamp would shift.
    const uint64_t now_ms = this->pub.type == NULL ? 0 : (uint64_t)timeMSec();

    pgbr_error_retry_state_add(this->state, errorTypeCode(type), message, now_ms);

    if (this->pub.type == NULL)
        this->pub.type = type;

    FUNCTION_TEST_RETURN_VOID();
}
