/***********************************************************************************************************************************
Gz Common

Thin C wrapper over the Rust implementation in `crates/pgbr-compress::gz`. Classification + message formatting + last-error
population happens in Rust (`pgbr_gz_error_classify_throw`); the C side only consults the bridge to decide whether to longjmp into
the nearest TRY block via `pgbr_error_throw_from_last`. This is the canonical shape new Rust-backed FFI shims should adopt — see
sub-issue #224 of the Phase 27 split.
***********************************************************************************************************************************/
#include <build.h>

#include "common/compress/gz/common.h"
#include "common/debug.h"
#include "common/error/error.h"
#include "pgbr_ffi.h"

/**********************************************************************************************************************************/
FN_EXTERN int
gzError(const int error)
{
    if (pgbr_gz_error_classify_throw(error) == 1)
        pgbr_error_throw_from_last(__FILE__, __func__, __LINE__);

    return error;
}
