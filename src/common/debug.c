/***********************************************************************************************************************************
Debug Routines

Thin C wrappers over the Rust implementation in `crates/pgbr-core::debug`. The string-into-buffer logic for `typeToLog`,
`objNameToLog` and `ptrToLog` lives in Rust; the byte-for-byte truncation contract from `strStcCat` / `strStcFmt` is reproduced by
`pgbr_core::debug::write_truncated`.

`objToLog` keeps its body in C because it dispatches to a C `ObjToLogFormat` callback that writes through the `StringStatic`
cursor. The null branch of `objToLog` reuses the Rust `pgbr_debug_type_to_log` shim with the literal `"null"` so all four functions
share a single rendering implementation across the FFI boundary.
***********************************************************************************************************************************/
#include <build.h>

#include "common/debug.h"
#include "pgbr_ffi.h"

/**********************************************************************************************************************************/
FN_EXTERN size_t
objToLog(const void *const object, const ObjToLogFormat formatFunc, char *const buffer, const size_t bufferSize)
{
    if (object == NULL)
        return pgbr_debug_type_to_log(NULL_Z, buffer, bufferSize);

    StringStatic debugLog = strStcInit(buffer, bufferSize);
    formatFunc(object, &debugLog);
    return strStcResultSize(&debugLog);
}

/**********************************************************************************************************************************/
FN_EXTERN size_t
objNameToLog(const void *const object, const char *const objectName, char *const buffer, const size_t bufferSize)
{
    return pgbr_debug_obj_name_to_log(object != NULL, objectName, buffer, bufferSize);
}

/**********************************************************************************************************************************/
FN_EXTERN size_t
ptrToLog(const void *const pointer, const char *const pointerName, char *const buffer, const size_t bufferSize)
{
    return pgbr_debug_ptr_to_log(pointer != NULL, pointerName, buffer, bufferSize);
}

/**********************************************************************************************************************************/
FN_EXTERN size_t
typeToLog(const char *const typeName, char *const buffer, const size_t bufferSize)
{
    return pgbr_debug_type_to_log(typeName, buffer, bufferSize);
}
