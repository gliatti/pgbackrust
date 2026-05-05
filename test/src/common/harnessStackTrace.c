/***********************************************************************************************************************************
Harness for Stack Trace Testing
***********************************************************************************************************************************/
#include <build.h>

#include "common/harnessDebug.h"
#include "common/harnessStackTrace.h"
#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Include shimmed C modules
***********************************************************************************************************************************/
{[SHIM_MODULE]}

/***********************************************************************************************************************************
Pre-Phase-30 the harness shimmed the static `stackTraceBackCallback` to force the libbacktrace path to return "no backtrace
data". After the migration the canonical state lives in `crates/pgbr-core::stack_trace`, so the same effect is now achieved by
flipping a Rust-side `force_no_backtrace` flag — the C side checks it inside `stackTraceToZ` before invoking `backtrace_full`.

The harness still keeps the `HAVE_LIBBACKTRACE` guard so builds without libbacktrace skip the install/uninstall calls entirely;
the flag is harmless on those builds (the C side never reads it).
***********************************************************************************************************************************/
#ifdef HAVE_LIBBACKTRACE

/**********************************************************************************************************************************/
void
hrnStackTraceBackShimInstall(void)
{
    FUNCTION_HARNESS_VOID();

    pgbr_stack_trace_force_no_backtrace_set(true);

    FUNCTION_HARNESS_RETURN_VOID();
}

/**********************************************************************************************************************************/
void
hrnStackTraceBackShimUninstall(void)
{
    FUNCTION_HARNESS_VOID();

    pgbr_stack_trace_force_no_backtrace_set(false);

    FUNCTION_HARNESS_RETURN_VOID();
}

#endif // HAVE_LIBBACKTRACE
