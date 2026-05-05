/***********************************************************************************************************************************
Error Retry Message Test
***********************************************************************************************************************************/
#include "common/harnessTime.h"
#include "common/type/list.h"

/***********************************************************************************************************************************
Differential helpers — `legacy_*` re-implementation of the pre-Phase-28 `errRetry*` body, kept verbatim from the C source that
existed before the Rust migration in `crates/pgbr-error::retry`. Runs alongside the new (Rust-backed) public API on identical
input sequences; the assertion at the bottom of the differential `testBegin` block requires byte-equal `errRetryMessage`
output between the two paths.

The legacy struct is private to the test file so it cannot collide with the production `ErrorRetry` (now an opaque pointer to the
Rust state). The legacy helpers also call `timeMSec()` directly, the same way the production code does — meaning each call
consumes one fixture from the `hrnTimeMSecSet` queue. The differential test sets up enough fixtures to feed both paths
identically.
***********************************************************************************************************************************/
typedef struct LegacyErrorRetryItem
{
    String *message;
    unsigned int total;
    const ErrorType *type;
    TimeMSec retryFirst;
    TimeMSec retryLast;
} LegacyErrorRetryItem;

typedef struct LegacyErrorRetry
{
    const ErrorType *type;
    const String *message;
    List *list;
    TimeMSec timeBegin;
} LegacyErrorRetry;

static LegacyErrorRetry *
legacy_errRetryNew(void)
{
    LegacyErrorRetry *const this = memNew(sizeof(LegacyErrorRetry));
    *this = (LegacyErrorRetry)
    {
        .timeBegin = timeMSec(),
        .list = lstNewP(sizeof(LegacyErrorRetryItem), .comparator = lstComparatorStr),
    };
    return this;
}

static void
legacy_errRetryAdd(LegacyErrorRetry *const this, const ErrorType *const type, const String *const message)
{
    if (this->type == NULL)
    {
        this->type = type;
        this->message = strNewZ(strZ(message));
    }
    else
    {
        const String *const messageFind = message;
        const TimeMSec retryTime = timeMSec() - this->timeBegin;
        LegacyErrorRetryItem *const error = lstFind(this->list, &messageFind);

        if (error == NULL)
        {
            const LegacyErrorRetryItem errorNew =
            {
                .type = type,
                .total = 1,
                .message = strDup(messageFind),
                .retryFirst = retryTime,
                .retryLast = retryTime,
            };

            lstAdd(this->list, &errorNew);
        }
        else
        {
            error->total++;
            error->retryLast = retryTime;
        }
    }
}

static String *
legacy_errRetryMessage(const LegacyErrorRetry *const this)
{
    String *const result = strCat(strNew(), this->message);

    for (unsigned int listIdx = 0; listIdx < lstSize(this->list); listIdx++)
    {
        const LegacyErrorRetryItem *const error = lstGet(this->list, listIdx);

        strCatFmt(result, "\n    [%s] ", errorTypeName(error->type));

        if (error->retryFirst == error->retryLast)
            strCatFmt(result, "on retry at %" PRIu64, error->retryFirst);
        else
            strCatFmt(
                result, "on %u retries from %" PRIu64 "-%" PRIu64, error->total, error->retryFirst, error->retryLast);

        strCatFmt(result, "ms: %s", strZ(error->message));
    }

    return result;
}

/***********************************************************************************************************************************
Test Run
***********************************************************************************************************************************/
static void
testRun(void)
{
    FUNCTION_HARNESS_VOID();

    // *****************************************************************************************************************************
    if (testBegin("ErrorRetry"))
    {
        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("retry (detail disabled)");
        {
            ErrorRetry *const retry = errRetryNew();

            TRY_BEGIN()
            {
                THROW(FormatError, "message1");
            }
            CATCH_ANY()
            {
                TEST_RESULT_VOID(errRetryAddP(retry), "add retry");
            }
            TRY_END();

            TRY_BEGIN()
            {
                THROW(KernelError, "message2");
            }
            CATCH_ANY()
            {
                TEST_RESULT_VOID(errRetryAddP(retry, errorType(), STR(errorMessage())), "add retry");
            }
            TRY_END();

            TEST_RESULT_BOOL(errRetryType(retry) == &FormatError, true, "error type");
            TEST_RESULT_STR_Z(
                errRetryMessage(retry),
                "message1\n"
                "[RETRY DETAIL OMITTED]",
                "error message");
        }

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("retry (detail enabled)");
        {
            hrnErrorRetryDetailEnable();

            TimeMSec timeList[] = {0, 50, 75, 150};
            hrnTimeMSecSet(timeList, LENGTH_OF(timeList));

            ErrorRetry *const retry = errRetryNew();

            TRY_BEGIN()
            {
                THROW(FormatError, "message1");
            }
            CATCH_ANY()
            {
                TEST_RESULT_VOID(errRetryAddP(retry), "add retry");
            }
            TRY_END();

            TRY_BEGIN()
            {
                THROW(FormatError, "message1");
            }
            CATCH_ANY()
            {
                TEST_RESULT_VOID(errRetryAddP(retry), "add retry");
            }
            TRY_END();

            TRY_BEGIN()
            {
                THROW(KernelError, "message2");
            }
            CATCH_ANY()
            {
                TEST_RESULT_VOID(errRetryAddP(retry), "add retry");
            }
            TRY_END();

            TRY_BEGIN()
            {
                THROW(ServiceError, "message1");
            }
            CATCH_ANY()
            {
                TEST_RESULT_VOID(errRetryAddP(retry), "add retry");
            }
            TRY_END();

            TEST_RESULT_BOOL(errRetryType(retry) == &FormatError, true, "error type");
            TEST_RESULT_STR_Z(
                errRetryMessage(retry),
                "message1\n"
                "    [FormatError] on 2 retries from 50-150ms: message1\n"
                "    [KernelError] on retry at 75ms: message2",
                "error message");
        }

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("differential parity vs legacy_* C re-implementation");
        {
            // Detail must be enabled so the harness routes through the real Rust formatter rather than the
            // "[RETRY DETAIL OMITTED]" shortcut. The harness's detail flag was already flipped on by the previous
            // testBegin block, but assert it here defensively in case the test order ever changes.
            hrnErrorRetryDetailEnable();

            // Eight scenarios cover: single error, dedup hit on first item, dedup hit on later item, distinct types
            // sharing a message, an empty-string message, a long message (~256 chars), interleaved messages, and a
            // single-add control.
            //
            // Each row enumerates {type, message} pairs. Both paths are driven through identical sequences from a
            // shared `hrnTimeMSecSet` fixture queue: every `add` consumes one fixture for the `timeMSec()` baseline
            // (`errRetryNew` / `legacy_errRetryNew`) plus one per `errRetryAdd` / `legacy_errRetryAdd`.
            const char *const longMsg =
                "a long retry message that exceeds 64 bytes to make sure the Rust formatter handles capacity growth "
                "without truncation when the deduplicated item list pushes a non-trivial entry into the buffer";

            typedef struct
            {
                const ErrorType *type;
                const char *message;
            } DiffStep;

            typedef struct
            {
                const char *title;
                const DiffStep *steps;
                unsigned int stepTotal;
            } DiffScenario;

            const DiffStep steps0[] = {{&FormatError, "only one"}};
            const DiffStep steps1[] = {
                {&FormatError, "msg-A"}, {&FormatError, "msg-A"}, {&FormatError, "msg-A"}
            };
            const DiffStep steps2[] = {
                {&FormatError, "first"}, {&KernelError, "second"}, {&KernelError, "second"}
            };
            const DiffStep steps3[] = {
                {&FormatError, "shared"}, {&KernelError, "shared"}, {&ServiceError, "shared"}
            };
            const DiffStep steps4[] = {
                {&FormatError, ""}, {&KernelError, ""}, {&FormatError, "non-empty"}
            };
            const DiffStep steps5[] = {{&FormatError, "preface"}, {&KernelError, longMsg}};
            const DiffStep steps6[] = {
                {&FormatError, "alpha"}, {&KernelError, "beta"}, {&FormatError, "alpha"},
                {&ServiceError, "gamma"}, {&KernelError, "beta"}
            };
            const DiffStep steps7[] = {{&KernelError, "lonely"}};

            const DiffScenario scenarios[] =
            {
                {.title = "single add", .steps = steps0, .stepTotal = LENGTH_OF(steps0)},
                {.title = "dedup three identical", .steps = steps1, .stepTotal = LENGTH_OF(steps1)},
                {.title = "first then dedup later", .steps = steps2, .stepTotal = LENGTH_OF(steps2)},
                {.title = "distinct types same message", .steps = steps3, .stepTotal = LENGTH_OF(steps3)},
                {.title = "empty messages", .steps = steps4, .stepTotal = LENGTH_OF(steps4)},
                {.title = "long retry message", .steps = steps5, .stepTotal = LENGTH_OF(steps5)},
                {.title = "interleaved dedup", .steps = steps6, .stepTotal = LENGTH_OF(steps6)},
                {.title = "single add second variant", .steps = steps7, .stepTotal = LENGTH_OF(steps7)},
            };

            for (unsigned int scenarioIdx = 0; scenarioIdx < LENGTH_OF(scenarios); scenarioIdx++)
            {
                const DiffScenario *const scenario = &scenarios[scenarioIdx];

                // The fixture queue size must match what each path consumes exactly, so the harness's auto-reset (when the
                // last entry is read) clears the slot before the next `hrnTimeMSecSet`. Both paths have the same consumption
                // pattern: `new()` reads one entry for the baseline, the first `add` reads zero (the first-error code path
                // skips `timeMSec()`), and each subsequent `add` reads one. Total = `stepTotal` entries per pass — index 0
                // is the baseline (`1000`), then `1000 + 17 * k` for the k-th non-first add.
                TimeMSec timeFixturesNew[32];
                TimeMSec timeFixturesLegacy[32];
                ASSERT(scenario->stepTotal <= 32);

                timeFixturesNew[0] = 1000;
                timeFixturesLegacy[0] = 1000;

                for (unsigned int stepIdx = 1; stepIdx < scenario->stepTotal; stepIdx++)
                {
                    timeFixturesNew[stepIdx] = 1000 + (TimeMSec)17 * stepIdx;
                    timeFixturesLegacy[stepIdx] = 1000 + (TimeMSec)17 * stepIdx;
                }

                // New (Rust-backed) path
                hrnTimeMSecSet(timeFixturesNew, scenario->stepTotal);
                ErrorRetry *const retry = errRetryNew();
                String *newMessage = NULL;
                const ErrorType *newType = NULL;

                MEM_CONTEXT_TEMP_BEGIN()
                {
                    for (unsigned int stepIdx = 0; stepIdx < scenario->stepTotal; stepIdx++)
                    {
                        errRetryAddP(retry, scenario->steps[stepIdx].type, STR(scenario->steps[stepIdx].message));
                    }

                    newType = errRetryType(retry);

                    MEM_CONTEXT_PRIOR_BEGIN()
                    {
                        newMessage = strDup(errRetryMessage(retry));
                    }
                    MEM_CONTEXT_PRIOR_END();
                }
                MEM_CONTEXT_TEMP_END();

                // Legacy path
                hrnTimeMSecSet(timeFixturesLegacy, scenario->stepTotal);
                String *legacyMessage = NULL;
                const ErrorType *legacyType = NULL;

                MEM_CONTEXT_TEMP_BEGIN()
                {
                    LegacyErrorRetry *const legacy = legacy_errRetryNew();

                    for (unsigned int stepIdx = 0; stepIdx < scenario->stepTotal; stepIdx++)
                    {
                        legacy_errRetryAdd(
                            legacy, scenario->steps[stepIdx].type, STR(scenario->steps[stepIdx].message));
                    }

                    legacyType = legacy->type;

                    MEM_CONTEXT_PRIOR_BEGIN()
                    {
                        legacyMessage = strDup(legacy_errRetryMessage(legacy));
                    }
                    MEM_CONTEXT_PRIOR_END();
                }
                MEM_CONTEXT_TEMP_END();

                TEST_RESULT_BOOL(
                    newType == legacyType, true, zNewFmt("scenario %u (%s): error type matches", scenarioIdx, scenario->title));
                TEST_RESULT_STR(
                    newMessage, legacyMessage,
                    zNewFmt("scenario %u (%s): formatted message matches", scenarioIdx, scenario->title));
            }
        }
    }

    FUNCTION_HARNESS_RETURN_VOID();
}
