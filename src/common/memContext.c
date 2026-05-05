/***********************************************************************************************************************************
Memory Context Manager

Phase 32D: the C `struct MemContext` body is gone — the byte-for-byte mirror in
`pgbr-core::mem_context` is the single source of truth. Every public function in this file is now
a thin FFI shim. The `memAllocInternal` / `memReAllocInternal` / `memFreeInternal` static helpers
stay because the first `testBegin` block of `memContextTest.c` exercises them directly with pinned
`MemoryError` diagnostics; everything else (`struct MemContext`, the optional-region typedefs, the
size-table, the static accessor helpers and the `contextTop` static) was deleted.
***********************************************************************************************************************************/
#include <build.h>

#include <stdlib.h>
#include <string.h>

#include "common/debug.h"
#include "common/macro.h"
#include "common/memContext.h"
#include "pgbr_ffi.h"

// Make sure the allocation is valid for the current memory context. The validity check lives in
// `pgbr-core::mem_context::mem_alloc_valid`; the macro just stringifies for the legacy
// `assertion '%s' failed` diagnostic.
#define ASSERT_ALLOC_MANY_VALID(alloc)                                                                                             \
    ASSERT(pgbr_mem_alloc_valid(alloc))

/***********************************************************************************************************************************
Constructor: prime the Rust-owned `TOP_CONTEXT` static and slot 0 of `memContextStack`. Runs once
per process at load time; `__attribute__((constructor))` is supported by GCC and Clang on every
platform pgBackRest builds against.
***********************************************************************************************************************************/
__attribute__((constructor))
static void
pgbr_mem_context_init_top_ctor(void)
{
    pgbr_mem_context_top_setup();
}

/***********************************************************************************************************************************
Wrapper around malloc() with error handling
***********************************************************************************************************************************/
static void *
memAllocInternal(const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    void *const buffer = malloc(size);

    if (buffer == NULL)
        THROW_FMT(MemoryError, "unable to allocate %zu bytes", size);

    FUNCTION_TEST_RETURN_P(VOID, buffer);
}

/***********************************************************************************************************************************
Allocate an array of pointers and set all entries to NULL. Phase 32C: not called from C production
code (the `pgbr-core::mem_context::mem_alloc_ptr_array` helper covers the live path); kept so the
test #include of this file keeps compiling.
***********************************************************************************************************************************/
__attribute__((unused)) static void *
memAllocPtrArrayInternal(const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    void **const buffer = memAllocInternal(size * sizeof(void *));

    for (size_t ptrIdx = 0; ptrIdx < size; ptrIdx++)
        buffer[ptrIdx] = NULL;

    FUNCTION_TEST_RETURN_P(VOID, buffer);
}

/***********************************************************************************************************************************
Wrapper around realloc() with error handling
***********************************************************************************************************************************/
static void *
memReAllocInternal(void *const bufferOld, const size_t sizeNew)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(VOID, bufferOld);
        FUNCTION_TEST_PARAM(SIZE, sizeNew);
    FUNCTION_TEST_END();

    ASSERT(bufferOld != NULL);

    void *const bufferNew = realloc(bufferOld, sizeNew);

    if (bufferNew == NULL)
        THROW_FMT(MemoryError, "unable to reallocate %zu bytes", sizeNew);

    FUNCTION_TEST_RETURN_P(VOID, bufferNew);
}

__attribute__((unused)) static void *
memReAllocPtrArrayInternal(void *const bufferOld, const size_t sizeOld, const size_t sizeNew)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(VOID, bufferOld);
        FUNCTION_TEST_PARAM(SIZE, sizeOld);
        FUNCTION_TEST_PARAM(SIZE, sizeNew);
    FUNCTION_TEST_END();

    void **const bufferNew = memReAllocInternal(bufferOld, sizeNew * sizeof(void *));

    for (size_t ptrIdx = sizeOld; ptrIdx < sizeNew; ptrIdx++)
        bufferNew[ptrIdx] = NULL;

    FUNCTION_TEST_RETURN_P(VOID, bufferNew);
}

/***********************************************************************************************************************************
Wrapper around free()
***********************************************************************************************************************************/
__attribute__((unused)) static void
memFreeInternal(void *const buffer)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(VOID, buffer);
    FUNCTION_TEST_END();

    ASSERT(buffer != NULL);

    free(buffer);

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN MemContext *
memContextNew(
#ifdef DEBUG
    const char *const name,
#endif
    const MemContextNewParam param)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRINGZ, name);
        FUNCTION_TEST_PARAM(UINT, param.childQty);
        FUNCTION_TEST_PARAM(UINT, param.allocQty);
        FUNCTION_TEST_PARAM(UINT, param.callbackQty);
        FUNCTION_TEST_PARAM(SIZE, param.allocExtra);
    FUNCTION_TEST_END();

#ifdef DEBUG
    ASSERT(name != NULL);
#endif
    ASSERT(param.childQty <= 1 || param.childQty == UINT8_MAX);
    ASSERT(param.allocQty <= 1 || param.allocQty == UINT8_MAX);
    ASSERT(param.callbackQty <= 1);
#ifdef DEBUG
    ASSERT(name[0] != '\0');
#endif
    ASSERT(pgbr_mem_context_field_child_qty(pgbr_mem_context_current()) != MEM_QTY_NONE);

    const PGBR_PgbrMemContextNewParam pgbrParam =
    {
        .dummy = false,
        .child_qty = (uint8_t)param.childQty,
        .alloc_qty = (uint8_t)param.allocQty,
        .callback_qty = (uint8_t)param.callbackQty,
        .alloc_extra = (uint16_t)param.allocExtra,
    };

    MemContext *const this = (MemContext *)pgbr_mem_context_new(
#ifdef DEBUG
        name,
#else
        NULL,
#endif
        pgbrParam, errorTryDepth());

    FUNCTION_TEST_RETURN(MEM_CONTEXT, this);
}

/**********************************************************************************************************************************/
FN_EXTERN void *
memContextAllocExtra(MemContext *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(MEM_CONTEXT, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(pgbr_mem_context_field_alloc_extra(this) != 0);

    FUNCTION_TEST_RETURN_P(VOID, pgbr_mem_context_alloc_extra(this));
}

/**********************************************************************************************************************************/
FN_EXTERN MemContext *
memContextFromAllocExtra(void *const allocExtra)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(VOID, allocExtra);
    FUNCTION_TEST_END();

    ASSERT(allocExtra != NULL);
    ASSERT(pgbr_mem_context_field_alloc_extra(pgbr_mem_context_from_alloc_extra(allocExtra)) != 0);

    FUNCTION_TEST_RETURN(MEM_CONTEXT, (MemContext *)pgbr_mem_context_from_alloc_extra(allocExtra));
}

/**********************************************************************************************************************************/
FN_EXTERN void
memContextCallbackSet(MemContext *const this, void (*const callbackFunction)(void *), void *const callbackArgument)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(MEM_CONTEXT, this);
        FUNCTION_TEST_PARAM(FUNCTIONP, callbackFunction);
        FUNCTION_TEST_PARAM_P(VOID, callbackArgument);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(pgbr_mem_context_field_active(this));
    ASSERT(callbackFunction != NULL);
    ASSERT(pgbr_mem_context_field_callback_qty(this) != MEM_QTY_NONE);

#ifdef DEBUG
    if (pgbr_mem_context_field_callback_initialized(this))
        THROW_FMT(AssertError, "callback is already set for context '%s'", pgbr_mem_context_field_name(this));
#endif

    pgbr_mem_context_callback_set(this, (PGBR_PgbrFreeCallback)callbackFunction, callbackArgument);

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN void
memContextCallbackClear(MemContext *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(MEM_CONTEXT, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(pgbr_mem_context_field_callback_qty(this) != MEM_QTY_NONE);
    ASSERT(pgbr_mem_context_field_active(this));

    pgbr_mem_context_callback_clear(this);

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN void *
memNew(const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    ASSERT(pgbr_mem_context_field_alloc_qty(pgbr_mem_context_current()) != MEM_QTY_NONE);

    void *const buffer = pgbr_mem_new(size);

    if (buffer == NULL)
        pgbr_error_throw_from_last(__FILE__, __func__, __LINE__);

    FUNCTION_TEST_RETURN_P(VOID, buffer);
}

/**********************************************************************************************************************************/
FN_EXTERN void *
memNewPtrArray(const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    ASSERT(pgbr_mem_context_field_alloc_qty(pgbr_mem_context_current()) != MEM_QTY_NONE);

    void *const buffer = pgbr_mem_new_ptr_array(size);

    if (buffer == NULL)
        pgbr_error_throw_from_last(__FILE__, __func__, __LINE__);

    FUNCTION_TEST_RETURN_P(VOID, buffer);
}

/**********************************************************************************************************************************/
FN_EXTERN void *
memResize(void *const buffer, const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(VOID, buffer);
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    ASSERT(buffer != NULL);

    void *const bufferNew = pgbr_mem_resize(buffer, size);

    if (bufferNew == NULL)
        pgbr_error_throw_from_last(__FILE__, __func__, __LINE__);

    FUNCTION_TEST_RETURN_P(VOID, bufferNew);
}

/**********************************************************************************************************************************/
FN_EXTERN void
memFree(void *const buffer)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(VOID, buffer);
    FUNCTION_TEST_END();

    void *const ctx = pgbr_mem_context_current();
    ASSERT(pgbr_mem_context_field_alloc_qty(ctx) != MEM_QTY_NONE);
    ASSERT(pgbr_mem_context_field_alloc_initialized(ctx));
    void *const alloc = pgbr_mem_context_alloc_header(buffer);

    if (pgbr_mem_context_field_alloc_qty(ctx) == MEM_QTY_ONE)
    {
        ASSERT(pgbr_mem_context_alloc_one_alloc(ctx) == alloc);
    }
    else
    {
        ASSERT(pgbr_mem_context_field_alloc_qty(ctx) == MEM_QTY_MANY);
        ASSERT_ALLOC_MANY_VALID(alloc);
    }

    pgbr_mem_free(buffer);

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN void
memContextMove(MemContext *const this, MemContext *const parentNew)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(MEM_CONTEXT, this);
        FUNCTION_TEST_PARAM(MEM_CONTEXT, parentNew);
    FUNCTION_TEST_END();

    ASSERT(parentNew != NULL);

#ifdef DEBUG
    if (this != NULL && pgbr_mem_context_field_context_parent(this) != parentNew)
    {
        void *const oldParent = pgbr_mem_context_field_context_parent(this);
        ASSERT(pgbr_mem_context_field_active(this));
        ASSERT(pgbr_mem_context_field_active(oldParent));
        ASSERT(pgbr_mem_context_field_child_qty(oldParent) != MEM_QTY_NONE);
        ASSERT(pgbr_mem_context_field_child_initialized(oldParent));

        if (pgbr_mem_context_field_child_qty(oldParent) == MEM_QTY_ONE)
        {
            ASSERT(pgbr_mem_context_child_one_context(oldParent) != NULL);
        }
        else
        {
            ASSERT(pgbr_mem_context_field_child_qty(oldParent) == MEM_QTY_MANY);
            ASSERT(
                pgbr_mem_context_child_many_list_at(oldParent, pgbr_mem_context_field_context_parent_idx(this)) == this);
        }

        ASSERT(pgbr_mem_context_field_active(parentNew));
        ASSERT(pgbr_mem_context_field_child_qty(parentNew) != MEM_QTY_NONE);

        if (pgbr_mem_context_field_child_qty(parentNew) == MEM_QTY_ONE)
        {
            ASSERT(
                !pgbr_mem_context_field_child_initialized(parentNew) ||
                pgbr_mem_context_child_one_context(parentNew) == NULL);
        }
        else
        {
            ASSERT(pgbr_mem_context_field_child_qty(parentNew) == MEM_QTY_MANY);
        }
    }
#endif

    pgbr_mem_context_move(this, parentNew);

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN void
memContextSwitch(MemContext *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(MEM_CONTEXT, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(pgbr_mem_context_field_active(this));

    pgbr_mem_context_switch(this, errorTryDepth());

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN void
memContextSwitchBack(void)
{
    FUNCTION_TEST_VOID();

#ifdef DEBUG
    PGBR_PgbrMemContextStackMismatch r = pgbr_mem_context_switch_back();
    if (r.kind == 1)
    {
        THROW_FMT(
            AssertError, "current context expected but new context '%s' found",
            pgbr_mem_context_field_name(r.mem_context));
    }
#else
    pgbr_mem_context_switch_back();
#endif

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN void
memContextKeep(void)
{
    FUNCTION_TEST_VOID();

#ifdef DEBUG
    PGBR_PgbrMemContextStackMismatch r = pgbr_mem_context_keep();
    if (r.kind == 2)
    {
        THROW_FMT(
            AssertError, "new context expected but current context '%s' found",
            pgbr_mem_context_field_name(r.mem_context));
    }
#else
    pgbr_mem_context_keep();
#endif

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN void
memContextDiscard(void)
{
    FUNCTION_TEST_VOID();

#ifdef DEBUG
    PGBR_PgbrMemContextStackMismatch r = pgbr_mem_context_discard((PGBR_PgbrFreeCallback)memContextFree);
    if (r.kind == 2)
    {
        THROW_FMT(
            AssertError, "new context expected but current context '%s' found",
            pgbr_mem_context_field_name(r.mem_context));
    }
#else
    pgbr_mem_context_discard((PGBR_PgbrFreeCallback)memContextFree);
#endif

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN MemContext *
memContextTop(void)
{
    FUNCTION_TEST_VOID();
    FUNCTION_TEST_RETURN(MEM_CONTEXT, (MemContext *)pgbr_mem_context_top());
}

FN_EXTERN MemContext *
memContextCurrent(void)
{
    FUNCTION_TEST_VOID();
    FUNCTION_TEST_RETURN(MEM_CONTEXT, (MemContext *)pgbr_mem_context_current());
}

FN_EXTERN MemContext *
memContextPrior(void)
{
    FUNCTION_TEST_VOID();
    FUNCTION_TEST_RETURN(MEM_CONTEXT, (MemContext *)pgbr_mem_context_prior());
}

/**********************************************************************************************************************************/
#ifdef DEBUG

FN_EXTERN size_t
memContextSize(const MemContext *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(MEM_CONTEXT, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(pgbr_mem_context_field_active(this));

    FUNCTION_TEST_RETURN(SIZE, pgbr_mem_context_size(this));
}

FN_EXTERN void
memContextAuditBegin(MemContextAuditState *const state)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(VOID, state);
    FUNCTION_TEST_END();

    ASSERT(state != NULL);
    ASSERT(state->memContext != NULL);
    ASSERT(
        state->memContext == memContextTop() ||
        pgbr_mem_context_field_sequence_new(state->memContext) != 0);

    pgbr_mem_context_audit_begin(state);

    FUNCTION_TEST_RETURN_VOID();
}

FN_EXTERN void
memContextAuditEnd(const MemContextAuditState *const state, const char *const returnType)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(VOID, state);
        FUNCTION_TEST_PARAM(STRINGZ, returnType);
    FUNCTION_TEST_END();

    const PGBR_PgbrAuditEndResult r = pgbr_mem_context_audit_end(state, returnType);

    if (r.kind == 1)
    {
        THROW_FMT(AssertError, "expected return type '%s' but found '%s'", returnType, r.return_type_invalid);
    }
    else if (r.kind == 2)
    {
        THROW_FMT(
            AssertError, "expected return type '%s' already found but also found '%s'", r.return_type_found,
            r.return_type_invalid);
    }

    FUNCTION_TEST_RETURN_VOID();
}

FN_EXTERN void *
memContextAuditAllocExtraName(void *const allocExtra, const char *const name)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(VOID, allocExtra);
        FUNCTION_TEST_PARAM(STRINGZ, name);
    FUNCTION_TEST_END();

    FUNCTION_TEST_RETURN_P(VOID, pgbr_mem_context_audit_alloc_extra_name(allocExtra, name));
}

#endif

/**********************************************************************************************************************************/
FN_EXTERN void
memContextClean(const unsigned int tryDepth, const bool fatal)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(UINT, tryDepth);
        FUNCTION_TEST_PARAM(BOOL, false);
    FUNCTION_TEST_END();

    pgbr_mem_context_clean(tryDepth, fatal, (PGBR_PgbrFreeCallback)memContextFree);

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN void
memContextFree(MemContext *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(MEM_CONTEXT, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(pgbr_mem_context_field_active(this));

    TRY_BEGIN()
    {
        pgbr_mem_context_free_callback_recurse(this);
    }
    FINALLY()
    {
        MemContext *const err = (MemContext *)pgbr_mem_context_free_release_recurse(this);

#ifdef DEBUG
        if (err != NULL)
            THROW_FMT(AssertError, "cannot free current context '%s'", pgbr_mem_context_field_name(err));
#else
        (void)err;
#endif
    }
    TRY_END();

    FUNCTION_TEST_RETURN_VOID();
}
