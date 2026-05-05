/***********************************************************************************************************************************
Memory Context Manager
***********************************************************************************************************************************/
#include <build.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/debug.h"
#include "common/macro.h"
#include "common/memContext.h"
#include "pgbr_ffi.h"

/***********************************************************************************************************************************
Contains information about a memory allocation. This header is placed at the beginning of every memory allocation returned to the
user by memNew(), etc. The advantage is that when an allocation is passed back by the user we know the location of the allocation
header by doing some pointer arithmetic. This is much faster than searching through a list.
***********************************************************************************************************************************/
typedef struct MemContextAlloc
{
    unsigned int allocIdx : 32;                                     // Index in the allocation list
    unsigned int size : 32;                                         // Allocation size (4GB max)
} MemContextAlloc;

// Get the allocation buffer pointer given the allocation header pointer
#define MEM_CONTEXT_ALLOC_BUFFER(header)                            ((MemContextAlloc *)header + 1)

// Get the allocation header pointer given the allocation buffer pointer
#define MEM_CONTEXT_ALLOC_HEADER(buffer)                            ((MemContextAlloc *)buffer - 1)

// Make sure the allocation is valid for the current memory context. This check only works correctly if the allocation is valid and
// allocated as one of many but belongs to another context. Otherwise, there is likely to be a segfault.
#define ASSERT_ALLOC_MANY_VALID(alloc)                                                                                             \
    ASSERT(                                                                                                                        \
        alloc != NULL && (uintptr_t)alloc != (uintptr_t)-sizeof(MemContextAlloc) &&                                                \
        alloc->allocIdx < memContextAllocMany(memContextStack[memContextCurrentStackIdx].memContext)->listSize &&                  \
        memContextAllocMany(memContextStack[memContextCurrentStackIdx].memContext)->list[alloc->allocIdx]);

/***********************************************************************************************************************************
Contains information about the memory context
***********************************************************************************************************************************/
// Quantity of child contexts, allocations, or callbacks
typedef enum
{
    memQtyNone = 0,                                                 // None for this type
    memQtyOne = 1,                                                  // One for this type
    memQtyMany = 2,                                                 // Many for this type
} MemQty;

// Main structure required by every mem context
struct MemContext
{
#ifdef DEBUG
    const char *name;                                               // Indicates what the context is being used for
    uint64_t sequenceNew;                                           // Sequence when this context was created (used for audit)
    bool active : 1;                                                // Is the context currently active?
#endif
    MemQty childQty : 2;                                            // How many child contexts can this context have?
    bool childInitialized : 1;                                      // Has the child context list been initialized?
    MemQty allocQty : 2;                                            // How many allocations can this context have?
    bool allocInitialized : 1;                                      // Has the allocation list been initialized?
    MemQty callbackQty : 2;                                         // How many callbacks can this context have?
    bool callbackInitialized : 1;                                   // Has the callback been initialized?
    size_t allocExtra : 16;                                         // Size of extra allocation (1kB max)

    unsigned int contextParentIdx;                                  // Index in the parent context list
    MemContext *contextParent;                                      // All contexts have a parent except top
};

// Mem context with one allocation
typedef struct MemContextAllocOne
{
    MemContextAlloc *alloc;                                         // Memory allocation created in this context
} MemContextAllocOne;

// Mem context with many allocations
typedef struct MemContextAllocMany
{
    MemContextAlloc **list;                                         // List of memory allocations created in this context
    unsigned int listSize;                                          // Size of alloc list (not the actual count of allocations)
    unsigned int freeIdx;                                           // Index of first free space in the alloc list
} MemContextAllocMany;

// Mem context with one child context
typedef struct MemContextChildOne
{
    MemContext *context;                                            // Context created in this context
} MemContextChildOne;

// Mem context with many child contexts
typedef struct MemContextChildMany
{
    MemContext **list;                                              // List of contexts created in this context
    unsigned int listSize;                                          // Size of child context list (not the actual count of contexts)
    unsigned int freeIdx;                                           // Index of first free space in the context list
} MemContextChildMany;

// Mem context with one callback
typedef struct MemContextCallbackOne
{
    void (*function)(void *);                                       // Function to call before the context is freed
    void *argument;                                                 // Argument to pass to callback function
} MemContextCallbackOne;

/***********************************************************************************************************************************
Layout-drift guard: the Rust mirror in `crates/pgbr-core/src/mem_context.rs` is byte-identical to these C structs and is gated by
the `c-debug` cargo feature (toggled via `PGBR_C_DEBUG=1` from the meson custom_target when `get_option('debug')` is true). Any
size drift here would corrupt malloc'd allocations the Rust algorithms in 32B-2 (#236) operate on; catch it at build time.
***********************************************************************************************************************************/
#if defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ == 8
#ifdef DEBUG
_Static_assert(sizeof(MemContext) == 32, "Rust mirror expects sizeof(MemContext) == 32 on 64-bit DEBUG");
#else
_Static_assert(sizeof(MemContext) == 16, "Rust mirror expects sizeof(MemContext) == 16 on 64-bit release");
#endif
_Static_assert(sizeof(MemContextChildMany) == 16, "Rust mirror expects sizeof(MemContextChildMany) == 16 on 64-bit");
_Static_assert(sizeof(MemContextAllocMany) == 16, "Rust mirror expects sizeof(MemContextAllocMany) == 16 on 64-bit");
_Static_assert(sizeof(MemContextCallbackOne) == 16, "Rust mirror expects sizeof(MemContextCallbackOne) == 16 on 64-bit");
_Static_assert(sizeof(MemContextAlloc) == 8, "Rust mirror expects sizeof(MemContextAlloc) == 8");
#endif

/***********************************************************************************************************************************
Possible sizes for the manifest based on options
***********************************************************************************************************************************/
// {uncrustify_off - formatting compressed to save space}
static const uint8_t memContextSizePossible[memQtyMany + 1][memQtyMany + 1][memQtyOne + 1] =
{
    // child none
    {// alloc none
     {/* callback none */ 0, /* callback one */ sizeof(MemContextCallbackOne)},
     // alloc one
     {/* callback none */ sizeof(MemContextAllocOne),
      /* callback one */ sizeof(MemContextAllocOne) + sizeof(MemContextCallbackOne)},
     // alloc many
     {/* callback none */ sizeof(MemContextAllocMany),
      /* callback one */ sizeof(MemContextAllocMany) + sizeof(MemContextCallbackOne)}},
    // child one
    {// alloc none
     {/* callback none */ sizeof(MemContextChildOne),
      /* callback one */ sizeof(MemContextChildOne) + sizeof(MemContextCallbackOne)},
     // alloc one
     {/* callback none */ sizeof(MemContextChildOne) + sizeof(MemContextAllocOne),
      /* callback one */ sizeof(MemContextChildOne) + sizeof(MemContextAllocOne) + sizeof(MemContextCallbackOne)},
     // alloc many
     {/* callback none */ sizeof(MemContextChildOne) + sizeof(MemContextAllocMany),
      /* callback one */ sizeof(MemContextChildOne) + sizeof(MemContextAllocMany) + sizeof(MemContextCallbackOne)}},
    // child many
    {// alloc none
     {/* callback none */ sizeof(MemContextChildMany),
      /* callback one */ sizeof(MemContextChildMany) + sizeof(MemContextCallbackOne)},
     // alloc one
     {/* callback none */ sizeof(MemContextChildMany) + sizeof(MemContextAllocOne),
      /* callback one */ sizeof(MemContextChildMany) + sizeof(MemContextAllocOne) + sizeof(MemContextCallbackOne)},
     // alloc many
     {/* callback none */ sizeof(MemContextChildMany) + sizeof(MemContextAllocMany),
      /* callback one */ sizeof(MemContextChildMany) + sizeof(MemContextAllocMany) + sizeof(MemContextCallbackOne)}},
};
// {uncrustify_on}

/***********************************************************************************************************************************
Get pointers to optional parts of the manifest
***********************************************************************************************************************************/
// Get pointer to child part
#define MEM_CONTEXT_CHILD_OFFSET(memContext)                        ((uint8_t *)(memContext + 1) + memContext->allocExtra)

// Used only by DEBUG-gated code (`memContextAuditBegin`, `memContextAuditEnd`, `memContextMove`'s
// asserts). In NDEBUG every caller compiles out, so tag the helpers `unused` to keep
// `-Werror=unused-function` happy. They stay declared because the test (`#include`s this `.c`
// directly) uses them.
__attribute__((unused)) static MemContextChildOne *
memContextChildOne(MemContext *const memContext)
{
    return (MemContextChildOne *)MEM_CONTEXT_CHILD_OFFSET(memContext);
}

__attribute__((unused)) static MemContextChildMany *
memContextChildMany(MemContext *const memContext)
{
    return (MemContextChildMany *)MEM_CONTEXT_CHILD_OFFSET(memContext);
}

// Get pointer to allocation part
#define MEM_CONTEXT_ALLOC_OFFSET(memContext)                                                                                       \
    ((uint8_t *)(memContext + 1) + memContextSizePossible[memContext->childQty][0][0] + memContext->allocExtra)

static MemContextAllocOne *
memContextAllocOne(MemContext *const memContext)
{
    return (MemContextAllocOne *)MEM_CONTEXT_ALLOC_OFFSET(memContext);
}

static MemContextAllocMany *
memContextAllocMany(MemContext *const memContext)
{
    return (MemContextAllocMany *)MEM_CONTEXT_ALLOC_OFFSET(memContext);
}

// Get pointer to callback part. The callers moved to Rust in 32B-3 (mem_context_callback_set /
// _clear / _callback_recurse), and the test does not yet reach into the callback region by hand,
// so this helper is unused on the C side. Tag it `unused` to keep `-Wunused-function` happy
// while preserving the symbol for the 32D rewrite which is expected to surface accessor parity.
__attribute__((unused)) static MemContextCallbackOne *
memContextCallbackOne(MemContext *const memContext)
{
    return
        (MemContextCallbackOne *)
        ((uint8_t *)(memContext + 1) +
         memContextSizePossible[memContext->childQty][memContext->allocQty][0] + memContext->allocExtra);
}

/***********************************************************************************************************************************
Top context

The top context always exists and can never be freed. All other contexts are children of the top context. The top context is
generally used to allocate memory that exists for the life of the program.
***********************************************************************************************************************************/
static struct MemContextTop
{
    MemContext memContext;
    MemContextChildMany memContextChildMany;
    MemContextAllocMany memContextAllocMany;
} contextTop =
{
    .memContext =
    {
#ifdef DEBUG
        .name = "TOP",
        .active = true,
#endif
        .childQty = memQtyMany,
        .allocQty = memQtyMany,
    },
};

/***********************************************************************************************************************************
Memory context stack types
***********************************************************************************************************************************/
typedef enum
{
    memContextStackTypeSwitch = 0,                                  // Context can be switched to allocate mem for new variables
    memContextStackTypeNew,                                         // Context to be tracked for error handling - cannot switch to
} MemContextStackType;

/***********************************************************************************************************************************
Mem context stack used to pop mem contexts and cleanup after an error

Phase 32 sub-issue A moves the storage for `memContextStack`, `memContextCurrentStackIdx`, `memContextMaxStackIdx` and
`memContextSequence` into Rust (see `crates/pgbr-core/src/mem_context.rs`) so `libpgbr_ffi.a` is self-contained: every test
binary that links the FFI archive resolves the `pgbr_mem_context_*` symbols without needing this `.c` file in its compile
list. The error / error-retry tests, which only need `pgbr_stack_trace_*` from the FFI archive, would otherwise fail at link
with `undefined reference to memContextStack`.

The C-side declarations below are `extern` aliases that point at the Rust-owned storage. The test (`test/src/test.c`
`#include`s this file directly) keeps reading `memContextStack[memContextCurrentStackIdx]` unchanged, and the
`ASSERT_ALLOC_MANY_VALID` macro stringification stays byte-identical.

Slot zero of `memContextStack` must hold `&contextTop`. Rust cannot static-init that pointer (it is a C symbol), so the
`pgbr_mem_context_init_top` hook is invoked from a `__attribute__((constructor))` below before `main` runs.
***********************************************************************************************************************************/
#define MEM_CONTEXT_STACK_MAX                                       128

struct MemContextStack
{
    MemContext *memContext;
    MemContextStackType type;
    unsigned int tryDepth;
};

extern struct MemContextStack memContextStack[MEM_CONTEXT_STACK_MAX];
extern unsigned int memContextCurrentStackIdx;
extern unsigned int memContextMaxStackIdx;
extern uint64_t memContextSequence;

// Constructor that primes `memContextStack[0].memContext` with `&contextTop` before `main`. Runs once per process at load
// time; `__attribute__((constructor))` is supported by GCC and Clang on every platform pgBackRest builds against.
//
// Phase 32B-3 sentinel: also assert that `pgbr_mem_context_struct_size()` (returned by the Rust
// mirror) matches `sizeof(struct MemContext)` on this side. The two must agree byte-for-byte; a
// disagreement means the Rust crate was built with the wrong `c-debug` cfg (the bug 32B-2
// surfaced when `test.pl` produced a libpgbr_ffi.a without `c-debug` even though the C side
// compiled with `-DDEBUG`). Aborting here is loud and obvious; silently mis-indexing bitfields is
// not.
__attribute__((constructor))
static void
pgbr_mem_context_init_top_ctor(void)
{
    if (pgbr_mem_context_struct_size() != sizeof(struct MemContext))
    {
        fprintf(
            stderr,
            "[pgbr] FATAL: Rust MemContext mirror size (%zu) != C sizeof(struct MemContext) (%zu).\n"
            "[pgbr] The libpgbr_ffi.a archive was built with the wrong `c-debug` cfg. Check that\n"
            "[pgbr] the meson custom_target invoking build-ffi.sh forwards `get_option('debug')`\n"
            "[pgbr] as the 5th argument; see test/src/command/test/build.c and src/meson.build.\n",
            pgbr_mem_context_struct_size(), sizeof(struct MemContext));
        abort();
    }

    pgbr_mem_context_init_top((MemContext *)&contextTop);
}

/***********************************************************************************************************************************
***********************************************************************************************************************************/
#ifdef DEBUG

FN_EXTERN void
memContextAuditBegin(MemContextAuditState *const state)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(VOID, state);
    FUNCTION_TEST_END();

    ASSERT(state != NULL);
    ASSERT(state->memContext != NULL);
    ASSERT(state->memContext == memContextTop() || state->memContext->sequenceNew != 0);

    if (state->memContext->childInitialized)
    {
        ASSERT(state->memContext->childQty != memQtyNone);

        if (state->memContext->childQty == memQtyOne)
        {
            MemContextChildOne *const memContextChild = memContextChildOne(state->memContext);

            if (memContextChild->context != NULL)
                state->sequenceContextNew = memContextChild->context->sequenceNew;
        }
        else
        {
            ASSERT(state->memContext->childQty == memQtyMany);
            MemContextChildMany *const memContextChild = memContextChildMany(state->memContext);

            for (unsigned int contextIdx = 0; contextIdx < memContextChild->listSize; contextIdx++)
            {
                if (memContextChild->list[contextIdx] != NULL &&
                    memContextChild->list[contextIdx]->sequenceNew > state->sequenceContextNew)
                {
                    state->sequenceContextNew = memContextChild->list[contextIdx]->sequenceNew;
                }
            }
        }
    }

    FUNCTION_TEST_RETURN_VOID();
}

static bool
memContextAuditNameMatch(const char *const actual, const char *const expected)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRINGZ, actual);
        FUNCTION_TEST_PARAM(STRINGZ, expected);
    FUNCTION_TEST_END();

    ASSERT(actual != NULL);
    ASSERT(expected != NULL);

    unsigned int actualIdx = 0;

    while (actual[actualIdx] != '\0' && actual[actualIdx] == expected[actualIdx])
        actualIdx++;

    FUNCTION_TEST_RETURN(
        BOOL,
        (actual[actualIdx] == '\0' || strncmp(actual + actualIdx, "::", 2) == 0) &&
        (expected[actualIdx] == '\0' || strcmp(expected + actualIdx, " *") == 0));
}

FN_EXTERN void
memContextAuditEnd(const MemContextAuditState *const state, const char *const returnType)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(VOID, state);
        FUNCTION_TEST_PARAM(STRINGZ, returnType);
    FUNCTION_TEST_END();

    if (state->returnTypeAny)
        FUNCTION_TEST_RETURN_VOID();

    if (state->memContext->childInitialized)
    {
        ASSERT(state->memContext->childQty != memQtyNone);

        const char *returnTypeInvalid = NULL;
        const char *returnTypeFound = NULL;

        if (state->memContext->childQty == memQtyOne)
        {
            MemContextChildOne *const memContextChild = memContextChildOne(state->memContext);

            if (memContextChild->context != NULL && memContextChild->context->sequenceNew > state->sequenceContextNew &&
                !memContextAuditNameMatch(memContextChild->context->name, returnType))
            {
                returnTypeInvalid = memContextChild->context->name;
            }
        }
        else
        {
            ASSERT(state->memContext->childQty == memQtyMany);
            MemContextChildMany *const memContextChild = memContextChildMany(state->memContext);

            for (unsigned int contextIdx = 0; contextIdx < memContextChild->listSize; contextIdx++)
            {
                if (memContextChild->list[contextIdx] != NULL &&
                    memContextChild->list[contextIdx]->sequenceNew > state->sequenceContextNew)
                {
                    if (memContextAuditNameMatch(memContextChild->list[contextIdx]->name, returnType))
                    {
                        if (returnTypeFound != NULL)
                        {
                            returnTypeInvalid = memContextChild->list[contextIdx]->name;
                            break;
                        }

                        returnTypeFound = memContextChild->list[contextIdx]->name;
                    }
                    else
                    {
                        returnTypeInvalid = memContextChild->list[contextIdx]->name;
                        break;
                    }
                }
            }
        }

        if (returnTypeInvalid != NULL)
        {
            if (returnTypeFound != NULL)
            {
                THROW_FMT(
                    AssertError, "expected return type '%s' already found but also found '%s'", returnTypeFound, returnTypeInvalid);
            }
            else
            {
                THROW_FMT(
                    AssertError, "expected return type '%s' but found '%s'", returnType, returnTypeInvalid);
            }
        }
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

    memContextFromAllocExtra(allocExtra)->name = name;

    FUNCTION_TEST_RETURN_P(VOID, allocExtra);
}

#endif

/***********************************************************************************************************************************
Wrapper around malloc() with error handling
***********************************************************************************************************************************/
static void *
memAllocInternal(const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    // Allocate memory
    void *const buffer = malloc(size);

    // Error when malloc fails
    if (buffer == NULL)
        THROW_FMT(MemoryError, "unable to allocate %zu bytes", size);

    // Return the buffer
    FUNCTION_TEST_RETURN_P(VOID, buffer);
}

/***********************************************************************************************************************************
Allocate an array of pointers and set all entries to NULL
***********************************************************************************************************************************/
static void *
memAllocPtrArrayInternal(const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    // Allocate memory
    void **const buffer = memAllocInternal(size * sizeof(void *));

    // Set all pointers to NULL
    for (size_t ptrIdx = 0; ptrIdx < size; ptrIdx++)
        buffer[ptrIdx] = NULL;

    // Return the buffer
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

    // Allocate memory
    void *const bufferNew = realloc(bufferOld, sizeNew);

    // Error when realloc fails
    if (bufferNew == NULL)
        THROW_FMT(MemoryError, "unable to reallocate %zu bytes", sizeNew);

    // Return the buffer
    FUNCTION_TEST_RETURN_P(VOID, bufferNew);
}

/***********************************************************************************************************************************
Wrapper around realloc() with error handling
***********************************************************************************************************************************/
static void *
memReAllocPtrArrayInternal(void *const bufferOld, const size_t sizeOld, const size_t sizeNew)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(VOID, bufferOld);
        FUNCTION_TEST_PARAM(SIZE, sizeOld);
        FUNCTION_TEST_PARAM(SIZE, sizeNew);
    FUNCTION_TEST_END();

    // Allocate memory
    void **const bufferNew = memReAllocInternal(bufferOld, sizeNew * sizeof(void *));

    // Set all new pointers to NULL
    for (size_t ptrIdx = sizeOld; ptrIdx < sizeNew; ptrIdx++)
        bufferNew[ptrIdx] = NULL;

    // Return the buffer
    FUNCTION_TEST_RETURN_P(VOID, bufferNew);
}

/***********************************************************************************************************************************
Wrapper around free()
***********************************************************************************************************************************/
static void
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
// Phase 32B-3: thin FFI shim. The C wrapper retains the parameter ASSERTs (name format, qty
// ranges) so the test still pins their stringified text. The actual allocation, parent-list
// registration and stack push happen in `pgbr-core::mem_context::mem_context_new`.
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
    ASSERT(((MemContext *)pgbr_mem_context_current())->childQty != memQtyNone);

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
    ASSERT(this->allocExtra != 0);

    FUNCTION_TEST_RETURN_P(VOID, this + 1);
}

/**********************************************************************************************************************************/
FN_EXTERN MemContext *
memContextFromAllocExtra(void *const allocExtra)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(VOID, allocExtra);
    FUNCTION_TEST_END();

    ASSERT(allocExtra != NULL);
    ASSERT(((MemContext *)allocExtra - 1)->allocExtra != 0);

    FUNCTION_TEST_RETURN(MEM_CONTEXT, (MemContext *)allocExtra - 1);
}

/**********************************************************************************************************************************/
// Phase 32B-3: thin FFI shim. The C wrapper retains the ASSERTs (the test pins their stringified
// text) and the DEBUG-only "callback is already set" check so the legacy diagnostic format
// survives. The actual write happens in `pgbr-core::mem_context::mem_context_callback_set`.
FN_EXTERN void
memContextCallbackSet(MemContext *const this, void (*const callbackFunction)(void *), void *const callbackArgument)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(MEM_CONTEXT, this);
        FUNCTION_TEST_PARAM(FUNCTIONP, callbackFunction);
        FUNCTION_TEST_PARAM_P(VOID, callbackArgument);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(this->active);
    ASSERT(callbackFunction != NULL);
    ASSERT(this->callbackQty != memQtyNone);

#ifdef DEBUG
    // Error if callback has already been set - there may be valid use cases for this in the future but error until one is found
    if (this->callbackInitialized)
        THROW_FMT(AssertError, "callback is already set for context '%s'", this->name);
#endif

    pgbr_mem_context_callback_set(this, (PGBR_PgbrFreeCallback)callbackFunction, callbackArgument);

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
// Phase 32B-3: thin FFI shim. ASSERTs stay on the C side so the test pins their text.
FN_EXTERN void
memContextCallbackClear(MemContext *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(MEM_CONTEXT, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(this->callbackQty != memQtyNone);
    ASSERT(this->active);

    pgbr_mem_context_callback_clear(this);

    FUNCTION_TEST_RETURN_VOID();
}

/***********************************************************************************************************************************
Find an available slot in the memory context's allocation list and allocate memory
***********************************************************************************************************************************/
static MemContextAlloc *
memContextAllocNew(const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    // Allocate memory
    MemContextAlloc *const result = memAllocInternal(sizeof(MemContextAlloc) + size);

    // Find space for the new allocation
    MemContext *const contextCurrent = memContextStack[memContextCurrentStackIdx].memContext;
    ASSERT(contextCurrent->allocQty != memQtyNone);

    if (contextCurrent->allocQty == memQtyOne)
    {
        MemContextAllocOne *const contextAlloc = memContextAllocOne(contextCurrent);
        ASSERT(!contextCurrent->allocInitialized || contextAlloc->alloc == NULL);

        // Initialize allocation header
        *result = (MemContextAlloc){.size = (unsigned int)(sizeof(MemContextAlloc) + size)};

        // Set pointer in allocation
        contextAlloc->alloc = result;
        contextCurrent->allocInitialized = true;
    }
    else
    {
        ASSERT(contextCurrent->allocQty == memQtyMany);

        MemContextAllocMany *const contextAlloc = memContextAllocMany(contextCurrent);

        // Initialize (free space will always be index 0)
        if (!contextCurrent->allocInitialized)
        {
            *contextAlloc = (MemContextAllocMany)
            {
                .list = memAllocPtrArrayInternal(MEM_CONTEXT_ALLOC_INITIAL_SIZE),
                .listSize = contextAlloc->listSize = MEM_CONTEXT_ALLOC_INITIAL_SIZE,
            };

            contextCurrent->allocInitialized = true;
        }
        else
        {
            for (; contextAlloc->freeIdx < contextAlloc->listSize; contextAlloc->freeIdx++)
                if (contextAlloc->list[contextAlloc->freeIdx] == NULL)
                    break;

            // If no space was found then allocate more
            if (contextAlloc->freeIdx == contextAlloc->listSize)
            {
                // Calculate new list size
                const unsigned int listSizeNew = contextAlloc->listSize * 2;

                // Reallocate memory before modifying anything else in case there is an error
                contextAlloc->list = memReAllocPtrArrayInternal(contextAlloc->list, contextAlloc->listSize, listSizeNew);

                // Set new size
                contextAlloc->listSize = listSizeNew;
            }
        }

        // Initialize allocation header
        *result = (MemContextAlloc){.allocIdx = contextAlloc->freeIdx, .size = (unsigned int)(sizeof(MemContextAlloc) + size)};

        // Set pointer in allocation list
        contextAlloc->list[contextAlloc->freeIdx] = result;

        // Update free index to next location. This location may not be free but it is where the search should start next time.
        contextAlloc->freeIdx++;
    }

    FUNCTION_TEST_RETURN_TYPE_P(MemContextAlloc, result);
}

/***********************************************************************************************************************************
Resize memory that has already been allocated
***********************************************************************************************************************************/
static MemContextAlloc *
memContextAllocResize(MemContextAlloc *alloc, const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(VOID, alloc);
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    // Resize the allocation
    alloc = memReAllocInternal(alloc, sizeof(MemContextAlloc) + size);
    alloc->size = (unsigned int)(sizeof(MemContextAlloc) + size);

    // Update pointer in allocation list in case the realloc moved the allocation
    MemContext *const currentContext = memContextStack[memContextCurrentStackIdx].memContext;
    ASSERT(currentContext->allocQty != memQtyNone);
    ASSERT(currentContext->allocInitialized);

    if (currentContext->allocQty == memQtyOne)
    {
        ASSERT(memContextAllocOne(currentContext)->alloc != NULL);
        memContextAllocOne(currentContext)->alloc = alloc;
    }
    else
    {
        ASSERT(currentContext->allocQty == memQtyMany);
        ASSERT_ALLOC_MANY_VALID(alloc);

        memContextAllocMany(currentContext)->list[alloc->allocIdx] = alloc;
    }

    FUNCTION_TEST_RETURN_TYPE_P(MemContextAlloc, alloc);
}

/**********************************************************************************************************************************/
FN_EXTERN void *
memNew(const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    FUNCTION_TEST_RETURN_P(VOID, MEM_CONTEXT_ALLOC_BUFFER(memContextAllocNew(size)));
}

/**********************************************************************************************************************************/
FN_EXTERN void *
memNewPtrArray(const size_t size)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(SIZE, size);
    FUNCTION_TEST_END();

    // Allocate pointer array
    void **const buffer = (void **const)MEM_CONTEXT_ALLOC_BUFFER(memContextAllocNew(size * sizeof(void *)));

    // Set pointers to NULL
    for (size_t ptrIdx = 0; ptrIdx < size; ptrIdx++)
        buffer[ptrIdx] = NULL;

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

    FUNCTION_TEST_RETURN_P(VOID, MEM_CONTEXT_ALLOC_BUFFER(memContextAllocResize(MEM_CONTEXT_ALLOC_HEADER(buffer), size)));
}

/**********************************************************************************************************************************/
FN_EXTERN void
memFree(void *const buffer)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM_P(VOID, buffer);
    FUNCTION_TEST_END();

    // Get the allocation
    MemContext *const contextCurrent = memContextStack[memContextCurrentStackIdx].memContext;
    ASSERT(contextCurrent->allocQty != memQtyNone);
    ASSERT(contextCurrent->allocInitialized);
    MemContextAlloc *const alloc = MEM_CONTEXT_ALLOC_HEADER(buffer);

    // Remove allocation from the context
    if (contextCurrent->allocQty == memQtyOne)
    {
        ASSERT(memContextAllocOne(contextCurrent)->alloc == alloc);
        memContextAllocOne(contextCurrent)->alloc = NULL;
    }
    else
    {
        ASSERT(contextCurrent->allocQty == memQtyMany);
        ASSERT_ALLOC_MANY_VALID(alloc);

        // If this allocation is before the current free allocation then make it the current free allocation
        MemContextAllocMany *const contextAlloc = memContextAllocMany(contextCurrent);

        if (alloc->allocIdx < contextAlloc->freeIdx)
            contextAlloc->freeIdx = alloc->allocIdx;

        // Null the allocation
        contextAlloc->list[alloc->allocIdx] = NULL;
    }

    // Free the allocation
    memFreeInternal(alloc);

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
// Phase 32B-3: thin FFI shim. The C wrapper retains the ASSERTs (the test pins their stringified
// text — see `'memContextChildMany(this->contextParent)->list[this->contextParentIdx] == this'`)
// and delegates the actual reparenting to `pgbr-core::mem_context::mem_context_move`.
FN_EXTERN void
memContextMove(MemContext *const this, MemContext *const parentNew)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(MEM_CONTEXT, this);
        FUNCTION_TEST_PARAM(MEM_CONTEXT, parentNew);
    FUNCTION_TEST_END();

    ASSERT(parentNew != NULL);

#ifdef DEBUG
    // Only validate if a valid mem context is provided and the old and new parents are not the same. The asserts capture the
    // legacy diagnostic stringification that the test still pins (`'this->active' failed`,
    // `'memContextChildMany(this->contextParent)->list[this->contextParentIdx] == this' failed`, etc.). They are DEBUG-only on
    // the C side because in NDEBUG every `ASSERT` expands to nothing — leaving empty if/else bodies that `-Werror=empty-body`
    // refuses to compile.
    if (this != NULL && this->contextParent != parentNew)
    {
        ASSERT(this->active);
        ASSERT(this->contextParent->active);
        ASSERT(this->contextParent->childQty != memQtyNone);
        ASSERT(this->contextParent->childInitialized);

        if (this->contextParent->childQty == memQtyOne)
        {
            ASSERT(memContextChildOne(this->contextParent)->context != NULL);
        }
        else
        {
            ASSERT(this->contextParent->childQty == memQtyMany);
            ASSERT(memContextChildMany(this->contextParent)->list[this->contextParentIdx] == this);
        }

        ASSERT(parentNew->active);
        ASSERT(parentNew->childQty != memQtyNone);

        if (parentNew->childQty == memQtyOne)
        {
            ASSERT(!parentNew->childInitialized || memContextChildOne(parentNew)->context == NULL);
        }
        else
        {
            ASSERT(parentNew->childQty == memQtyMany);
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
    ASSERT(this->active);

    // Phase 32A: stack mutation lives in Rust now. The Rust side asserts on overflow.
    pgbr_mem_context_switch(this, errorTryDepth());

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN void
memContextSwitchBack(void)
{
    FUNCTION_TEST_VOID();

    // Phase 32A: stack mutation lives in Rust now. On a type mismatch the Rust side returns the
    // offending top entry without popping (so the legacy "throw before pop" semantics survive in
    // DEBUG builds).
#ifdef DEBUG
    PGBR_PgbrMemContextStackMismatch r = pgbr_mem_context_switch_back();
    if (r.kind == 1)
    {
        THROW_FMT(
            AssertError, "current context expected but new context '%s' found",
            ((MemContext *)r.mem_context)->name);
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
            ((MemContext *)r.mem_context)->name);
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

    // Phase 32A: stack mutation in Rust. On type-mismatch (kind == 2) the Rust side returns the
    // offending top entry without freeing or popping; the legacy DEBUG diagnostic is preserved.
    // On success Rust invokes `memContextFree` (passed by pointer) and pops.
#ifdef DEBUG
    PGBR_PgbrMemContextStackMismatch r = pgbr_mem_context_discard((PGBR_PgbrFreeCallback)memContextFree);
    if (r.kind == 2)
    {
        THROW_FMT(
            AssertError, "new context expected but current context '%s' found",
            ((MemContext *)r.mem_context)->name);
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
    FUNCTION_TEST_RETURN(MEM_CONTEXT, (MemContext *)&contextTop);
}

/**********************************************************************************************************************************/
FN_EXTERN MemContext *
memContextCurrent(void)
{
    FUNCTION_TEST_VOID();
    FUNCTION_TEST_RETURN(MEM_CONTEXT, (MemContext *)pgbr_mem_context_current());
}

/**********************************************************************************************************************************/
FN_EXTERN MemContext *
memContextPrior(void)
{
    FUNCTION_TEST_VOID();
    FUNCTION_TEST_RETURN(MEM_CONTEXT, (MemContext *)pgbr_mem_context_prior());
}

/**********************************************************************************************************************************/
#ifdef DEBUG

// Phase 32B-3: thin FFI shim. The recursive size accounting moved to
// `pgbr-core::mem_context::mem_context_size`.
FN_EXTERN size_t
memContextSize(const MemContext *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(MEM_CONTEXT, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(this->active);

    FUNCTION_TEST_RETURN(SIZE, pgbr_mem_context_size(this));
}

#endif // DEBUG

/**********************************************************************************************************************************/
FN_EXTERN void
memContextClean(const unsigned int tryDepth, const bool fatal)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(UINT, tryDepth);
        FUNCTION_TEST_PARAM(BOOL, false);
    FUNCTION_TEST_END();

    // Phase 32A: stack unwinding lives in Rust now. The Rust side invokes `memContextFree`
    // (passed by pointer) for non-fatal frees so the link-time dependency stays in this file.
    pgbr_mem_context_clean(tryDepth, fatal, (PGBR_PgbrFreeCallback)memContextFree);

    FUNCTION_TEST_RETURN_VOID();
}

/**********************************************************************************************************************************/
// Phase 32B-3: thin FFI shim. The two halves of the legacy `memContextFree` —
// `memContextCallbackRecurse` and `memContextFreeRecurse` — moved into
// `pgbr-core::mem_context::mem_context_callback_recurse` and `_free_release_recurse`. The
// `TRY_BEGIN`/`FINALLY`/`TRY_END` wrapper stays on the C side because callbacks may longjmp via
// the C error machinery, and setjmp/longjmp through Rust frames is undefined behaviour. The
// release-half returns the offending context pointer when the DEBUG-only "cannot free current
// context" invariant is violated; the C wrapper rethrows with the legacy diagnostic.
FN_EXTERN void
memContextFree(MemContext *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(MEM_CONTEXT, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(this->active);

    TRY_BEGIN()
    {
        pgbr_mem_context_free_callback_recurse(this);
    }
    FINALLY()
    {
        MemContext *const err = (MemContext *)pgbr_mem_context_free_release_recurse(this);

#ifdef DEBUG
        if (err != NULL)
            THROW_FMT(AssertError, "cannot free current context '%s'", err->name);
#else
        (void)err;
#endif
    }
    TRY_END();

    FUNCTION_TEST_RETURN_VOID();
}
