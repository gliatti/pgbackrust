/***********************************************************************************************************************************
Error Retry Message Harness
***********************************************************************************************************************************/
#include <build.h>

#include "common/harnessDebug.h"
#include "common/harnessErrorRetry.h"

/***********************************************************************************************************************************
Include shimmed C modules
***********************************************************************************************************************************/
{[SHIM_MODULE]}

static struct
{
    bool detailEnable;                                              // Error retry details enabled (not the default)
} hrnErrorRetryLocal;

/**********************************************************************************************************************************/
String *
errRetryMessage(const ErrorRetry *const this)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(ERROR_RETRY, this);
    FUNCTION_HARNESS_END();

    String *result = NULL;

    if (!hrnErrorRetryLocal.detailEnable)
    {
        // Reach into the Rust state via the same FFI helpers the production shim uses. The C struct moved to an opaque pointer
        // model when retry.c was migrated in Phase 28, so the legacy "this->message / this->list" inspection no longer compiles —
        // the equivalent reads are now `pgbr_error_retry_state_first_message` and `pgbr_error_retry_state_item_count`.
        const char *const firstMsg = pgbr_error_retry_state_first_message(this->state);

        ASSERT(firstMsg != NULL);

        result = strCatZ(strNew(), firstMsg);

        if (pgbr_error_retry_state_item_count(this->state) > 0)
            strCatZ(result, "\n[RETRY DETAIL OMITTED]");
    }
    else
        result = errRetryMessage_SHIMMED(this);

    FUNCTION_HARNESS_RETURN(STRING, result);
}

/**********************************************************************************************************************************/
void
hrnErrorRetryDetailEnable(void)
{
    FUNCTION_HARNESS_VOID();

    hrnErrorRetryLocal.detailEnable = true;

    FUNCTION_HARNESS_RETURN_VOID();
}

void
hrnErrorRetryDetailDisable(void)
{
    FUNCTION_HARNESS_VOID();

    hrnErrorRetryLocal.detailEnable = false;

    FUNCTION_HARNESS_RETURN_VOID();
}
