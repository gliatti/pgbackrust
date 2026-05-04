/***********************************************************************************************************************************
CRC-32 Calculation

Thin C wrapper over the Rust implementation in `crates/pgbr-postgres`. The actual CRC-32C computation lives in libpgbr_ffi.a; this
file keeps `src/postgres/interface/crc32.h` byte-identical to the legacy version.
***********************************************************************************************************************************/
#include <build.h>

#include "postgres/interface/crc32.h"
#include "pgbr_ffi.h"

/**********************************************************************************************************************************/
FN_EXTERN uint32_t
crc32cOne(const uint8_t *data, size_t size)
{
    return pgbr_crc32c_one(data, size);
}
