/***********************************************************************************************************************************
Object Helper Macros and Functions

Thin C shims over the Rust bodies in `crates/pgbr-core::object`. The three public functions are pure pointer arithmetic on the
`allocExtra` boundary — `objMove` and `objMoveToInterface` resolve the owning `MemContext` and forward to `memContextMove`;
`objFree` forwards to the legacy C `memContextFree` through the `PgbrFreeCallback` parameter.
***********************************************************************************************************************************/
#include <build.h>

#include "common/type/object.h"
#include "pgbr_ffi.h"

/**********************************************************************************************************************************/
FN_EXTERN void *
objMove(THIS_VOID, MemContext *const parentNew)
{
    return pgbr_obj_move(thisVoid, parentNew);
}

/**********************************************************************************************************************************/
FN_EXTERN void *
objMoveToInterface(THIS_VOID, void *const interfaceVoid, const MemContext *const current)
{
    return pgbr_obj_move_to_interface(thisVoid, interfaceVoid, current);
}

/**********************************************************************************************************************************/
FN_EXTERN void
objFree(THIS_VOID)
{
    pgbr_obj_free(thisVoid, (PGBR_PgbrFreeCallback)memContextFree);
}
