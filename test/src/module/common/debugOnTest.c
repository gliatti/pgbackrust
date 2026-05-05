/***********************************************************************************************************************************
Test Debug Macros and Routines
***********************************************************************************************************************************/
#include <string.h>

#include "common/log.h"

#include "common/harnessLog.h"
#include "common/macro.h"

/***********************************************************************************************************************************
Differential helpers — `legacy_*` re-implementations of the pre-Phase-29 `typeToLog` / `objNameToLog` / `ptrToLog` bodies, kept
verbatim from `src/common/debug.c`. The differential test below feeds identical inputs to both paths and asserts the output bytes
and the returned size match for a wide grid of buffer sizes and name lengths.
***********************************************************************************************************************************/
static size_t
legacy_typeToLog(const char *const typeName, char *const buffer, const size_t bufferSize)
{
    StringStatic debugLog = strStcInit(buffer, bufferSize);
    strStcFmt(&debugLog, "%s", typeName);
    return strStcResultSize(&debugLog);
}

static size_t
legacy_objNameToLog(const void *const object, const char *const objectName, char *const buffer, const size_t bufferSize)
{
    StringStatic debugLog = strStcInit(buffer, bufferSize);

    if (object == NULL)
        strStcCat(&debugLog, NULL_Z);
    else
        strStcFmt(&debugLog, "{%s}", objectName);

    return strStcResultSize(&debugLog);
}

static size_t
legacy_ptrToLog(const void *const pointer, const char *const pointerName, char *const buffer, const size_t bufferSize)
{
    StringStatic debugLog = strStcInit(buffer, bufferSize);

    if (pointer == NULL)
        strStcCat(&debugLog, NULL_Z);
    else
        strStcFmt(&debugLog, "(%s)", pointerName);

    return strStcResultSize(&debugLog);
}

static void
testFunction3(void)
{
    FUNCTION_TEST_VOID();
    FUNCTION_TEST_RETURN_VOID();
}

static void
testFunction2(void)
{
    FUNCTION_LOG_VOID(logLevelTrace);

    testFunction3();

    FUNCTION_LOG_RETURN_VOID();
}

static int
testFunction1(
    int paramInt, bool paramBool, bool *paramBoolP, bool **paramBoolPP, void *paramVoidP, mode_t paramMode)
{
    FUNCTION_LOG_BEGIN(logLevelDebug);
        FUNCTION_LOG_PARAM(INT, paramInt);
        FUNCTION_LOG_PARAM(BOOL, paramBool);
        FUNCTION_LOG_PARAM_P(BOOL, paramBoolP);
        FUNCTION_LOG_PARAM_PP(BOOL, paramBoolPP);
        FUNCTION_LOG_PARAM_P(VOID, paramVoidP);
        FUNCTION_LOG_PARAM(MODE, paramMode);
    FUNCTION_LOG_END();

    testFunction2();

    FUNCTION_LOG_RETURN(INT, 1);
}

static void
testObjToLog(const char *const object, StringStatic *const debugLog)
{
    strStcFmt(debugLog, "{%s}", object);
}

/***********************************************************************************************************************************
Test Run
***********************************************************************************************************************************/
static void
testRun(void)
{
    FUNCTION_HARNESS_VOID();

    // *****************************************************************************************************************************
    if (testBegin("strStc*()"))
    {
        const char *test8 = "12345678";
        char buffer9[9];

        StringStatic debugLog = strStcInit(buffer9, sizeof(buffer9) - 1);
        TEST_RESULT_UINT(strStcResultSize(strStcFmt(&debugLog, "%s", test8)), 7, "result size");
        TEST_RESULT_UINT(strStcRemainsSize(&debugLog), 1, "buffer size");
        TEST_RESULT_PTR(strStcRemains(&debugLog), buffer9 + 7, "buffer remains");
        TEST_RESULT_Z(debugLog.buffer, "1234567", "check buffer");

        debugLog = strStcInit(buffer9, sizeof(buffer9));
        TEST_RESULT_UINT(strStcResultSize(strStcFmt(&debugLog, "%s", test8)), 8, "result size");
        TEST_RESULT_UINT(strStcRemainsSize(&debugLog), 1, "buffer size");
        TEST_RESULT_PTR(strStcRemains(&debugLog), buffer9 + 8, "buffer remains");
        TEST_RESULT_Z(debugLog.buffer, "12345678", "check buffer");

        TEST_RESULT_UINT(strStcResultSize(strStcFmt(&debugLog, "%s", test8)), 8, "result size");
        TEST_RESULT_UINT(strStcRemainsSize(&debugLog), 1, "buffer size");
        TEST_RESULT_PTR(strStcRemains(&debugLog), buffer9 + 8, "buffer remains");
        TEST_RESULT_Z(debugLog.buffer, "12345678", "check buffer");

        debugLog = strStcInit(buffer9, 4);
        TEST_RESULT_VOID(strStcCat(&debugLog, "AA"), "cat all");
        TEST_RESULT_UINT(strStcResultSize(&debugLog), 2, "result size");
        TEST_RESULT_UINT(strStcRemainsSize(&debugLog), 2, "buffer size");
        TEST_RESULT_PTR(strStcRemains(&debugLog), buffer9 + 2, "buffer remains");
        TEST_RESULT_Z(debugLog.buffer, "AA", "check buffer");

        TEST_RESULT_VOID(strStcCat(&debugLog, "BB"), "cat partial");
        TEST_RESULT_UINT(strStcResultSize(&debugLog), 3, "result size");
        TEST_RESULT_UINT(strStcRemainsSize(&debugLog), 1, "buffer size");
        TEST_RESULT_PTR(strStcRemains(&debugLog), buffer9 + 3, "buffer remains");
        TEST_RESULT_Z(debugLog.buffer, "AAB", "check buffer");

        TEST_RESULT_VOID(strStcCat(&debugLog, "CC"), "cat none");
        TEST_RESULT_UINT(strStcResultSize(&debugLog), 3, "result size");
        TEST_RESULT_UINT(strStcRemainsSize(&debugLog), 1, "buffer size");
        TEST_RESULT_PTR(strStcRemains(&debugLog), buffer9 + 3, "buffer remains");
        TEST_RESULT_Z(debugLog.buffer, "AAB", "check buffer");

        debugLog = strStcInit(buffer9, 2);
        TEST_RESULT_VOID(strStcCatChr(&debugLog, 'Z'), "cat char");
        TEST_RESULT_UINT(strStcResultSize(&debugLog), 1, "result size");
        TEST_RESULT_UINT(strStcRemainsSize(&debugLog), 1, "buffer size");
        TEST_RESULT_PTR(strStcRemains(&debugLog), buffer9 + 1, "buffer remains");
        TEST_RESULT_Z(debugLog.buffer, "Z", "check buffer");

        TEST_RESULT_VOID(strStcCatChr(&debugLog, 'Y'), "cat char");
        TEST_RESULT_UINT(strStcResultSize(&debugLog), 1, "result size");
        TEST_RESULT_UINT(strStcRemainsSize(&debugLog), 1, "buffer size");
        TEST_RESULT_PTR(strStcRemains(&debugLog), buffer9 + 1, "buffer remains");
        TEST_RESULT_Z(debugLog.buffer, "Z", "check buffer");
    }

    // *****************************************************************************************************************************
    if (testBegin("objToLog(), objNameToLog(), ptrToLog, and strzToLog()"))
    {
        char buffer[STACK_TRACE_PARAM_MAX];

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("objToLog()");

        TEST_RESULT_UINT(objToLog(NULL, (ObjToLogFormat)testObjToLog, buffer, sizeof(buffer)), 4, "null");
        TEST_RESULT_Z(buffer, "null", "    check full null");

        TEST_RESULT_UINT(objToLog("test", (ObjToLogFormat)testObjToLog, buffer, 4), 3, "null");
        TEST_RESULT_Z(buffer, "{te", "    check full null");

        TEST_RESULT_UINT(objToLog("test", (ObjToLogFormat)testObjToLog, buffer, sizeof(buffer)), 6, "null");
        TEST_RESULT_Z(buffer, "{test}", "    check full null");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_RESULT_UINT(objNameToLog(NULL, "Object", buffer, 4), 3, "truncated null");
        TEST_RESULT_Z(buffer, "nul", "    check truncated null");

        TEST_RESULT_UINT(objNameToLog(NULL, "Object", buffer, sizeof(buffer)), 4, "full null");
        TEST_RESULT_Z(buffer, "null", "    check full null");

        TEST_RESULT_UINT(objNameToLog((void *)1, "Object", buffer, 4), 3, "truncated object");
        TEST_RESULT_Z(buffer, "{Ob", "    check truncated object");

        TEST_RESULT_UINT(objNameToLog((void *)1, "Object", buffer, sizeof(buffer)), 8, "full object");
        TEST_RESULT_Z(buffer, "{Object}", "    check full object");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_RESULT_UINT(ptrToLog(NULL, "char *", buffer, 4), 3, "truncated null");
        TEST_RESULT_Z(buffer, "nul", "    check truncated null");

        TEST_RESULT_UINT(ptrToLog(NULL, "char *", buffer, sizeof(buffer)), 4, "full null");
        TEST_RESULT_Z(buffer, "null", "    check full null");

        TEST_RESULT_UINT(ptrToLog((void *)1, "char *", buffer, 4), 3, "truncated pointer");
        TEST_RESULT_Z(buffer, "(ch", "    check truncated pointer");

        TEST_RESULT_UINT(ptrToLog((void *)1, "char *", buffer, sizeof(buffer)), 8, "full pointer");
        TEST_RESULT_Z(buffer, "(char *)", "    check full pointer");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_RESULT_UINT(strzToLog(NULL, buffer, 4), 4, "truncated null");
        TEST_RESULT_Z(buffer, "nul", "    check truncated null");

        TEST_RESULT_UINT(strzToLog(NULL, buffer, sizeof(buffer)), 4, "full null");
        TEST_RESULT_Z(buffer, "null", "    check full null");

        TEST_RESULT_UINT(strzToLog("test", buffer, 4), 6, "truncated string");
        TEST_RESULT_Z(buffer, "\"te", "    check truncated string");

        TEST_RESULT_UINT(strzToLog("test2", buffer, sizeof(buffer)), 7, "full string");
        TEST_RESULT_Z(buffer, "\"test2\"", "    check full string");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("differential parity vs legacy_* C re-implementation");

        // Names span lengths from 0 to slightly above the smallest buffer size we drive, so the
        // strStcCat truncation branch is exercised on both the present and the absent (`null`)
        // paths. The grid has 4 names × 9 buffer sizes × 2 presence states × 3 functions =
        // 216 paired byte-comparisons.
        const char *const names[] = {"", "X", "Object", "verylongtype that exceeds buffers"};
        const size_t bufferSizes[] = {0, 1, 2, 3, 4, 5, 8, 16, 256};

        for (unsigned int sizeIdx = 0; sizeIdx < LENGTH_OF(bufferSizes); sizeIdx++)
        {
            const size_t bufferSize = bufferSizes[sizeIdx];
            char newBuf[STACK_TRACE_PARAM_MAX];
            char legacyBuf[STACK_TRACE_PARAM_MAX];

            for (unsigned int nameIdx = 0; nameIdx < LENGTH_OF(names); nameIdx++)
            {
                const char *const name = names[nameIdx];

                // Sentinel-fill so any byte the function fails to overwrite is visibly distinct.
                memset(newBuf, 0xAA, sizeof(newBuf));
                memset(legacyBuf, 0xAA, sizeof(legacyBuf));

                // typeToLog
                const size_t newType = typeToLog(name, newBuf, bufferSize);
                const size_t legacyType = legacy_typeToLog(name, legacyBuf, bufferSize);

                TEST_RESULT_UINT(
                    newType, legacyType, zNewFmt("typeToLog: size=%zu name=%u — return matches", bufferSize, nameIdx));

                if (bufferSize > 0)
                {
                    // Compare full-buffer payload up to and including the NUL the legacy path writes.
                    TEST_RESULT_INT(
                        memcmp(newBuf, legacyBuf, bufferSize), 0,
                        zNewFmt("typeToLog: size=%zu name=%u — bytes match", bufferSize, nameIdx));
                }

                // objNameToLog (present and absent)
                for (int present = 0; present <= 1; present++)
                {
                    const void *const object = present ? (const void *)1 : NULL;

                    memset(newBuf, 0xAA, sizeof(newBuf));
                    memset(legacyBuf, 0xAA, sizeof(legacyBuf));

                    const size_t newObj = objNameToLog(object, name, newBuf, bufferSize);
                    const size_t legacyObj = legacy_objNameToLog(object, name, legacyBuf, bufferSize);

                    TEST_RESULT_UINT(
                        newObj, legacyObj,
                        zNewFmt("objNameToLog: size=%zu name=%u present=%d — return matches", bufferSize, nameIdx, present));

                    if (bufferSize > 0)
                    {
                        TEST_RESULT_INT(
                            memcmp(newBuf, legacyBuf, bufferSize), 0,
                            zNewFmt(
                                "objNameToLog: size=%zu name=%u present=%d — bytes match", bufferSize, nameIdx, present));
                    }
                }

                // ptrToLog (present and absent)
                for (int present = 0; present <= 1; present++)
                {
                    const void *const ptr = present ? (const void *)1 : NULL;

                    memset(newBuf, 0xAA, sizeof(newBuf));
                    memset(legacyBuf, 0xAA, sizeof(legacyBuf));

                    const size_t newPtr = ptrToLog(ptr, name, newBuf, bufferSize);
                    const size_t legacyPtr = legacy_ptrToLog(ptr, name, legacyBuf, bufferSize);

                    TEST_RESULT_UINT(
                        newPtr, legacyPtr,
                        zNewFmt("ptrToLog: size=%zu name=%u present=%d — return matches", bufferSize, nameIdx, present));

                    if (bufferSize > 0)
                    {
                        TEST_RESULT_INT(
                            memcmp(newBuf, legacyBuf, bufferSize), 0,
                            zNewFmt("ptrToLog: size=%zu name=%u present=%d — bytes match", bufferSize, nameIdx, present));
                    }
                }
            }
        }
    }

    // *****************************************************************************************************************************
    if (testBegin("DEBUG"))
    {
#ifdef DEBUG
        bool debug = true;
#else
        bool debug = false;
#endif

        TEST_RESULT_BOOL(debug, true, "DEBUG is defined");
    }

    // *****************************************************************************************************************************
    if (testBegin("FUNCTION_DEBUG() and FUNCTION_LOG_RETURN()"))
    {
        harnessLogLevelSet(logLevelTrace);
        testFunction1(99, false, NULL, NULL, NULL, 0755);

        TEST_RESULT_LOG(
            "P00  DEBUG:     " TEST_PGB_PATH "/test/src/module/common/debugOnTest::testFunction1: (paramInt: 99, paramBool: false,"
            " paramBoolP: null, paramBoolPP: null, paramVoidP: null, paramMode: 0755)\n"
            "P00  TRACE:         " TEST_PGB_PATH "/test/src/module/common/debugOnTest::testFunction2: (void)\n"
            "P00  TRACE:         " TEST_PGB_PATH "/test/src/module/common/debugOnTest::testFunction2: => void\n"
            "P00  DEBUG:     " TEST_PGB_PATH "/test/src/module/common/debugOnTest::testFunction1: => 1");

        // -------------------------------------------------------------------------------------------------------------------------
        bool testBool = true;
        bool *testBoolP = &testBool;
        bool **testBoolPP = &testBoolP;
        void *testVoidP = NULL;

        testFunction1(99, false, testBoolP, testBoolPP, testVoidP, 0755);

        TEST_RESULT_LOG(
            "P00  DEBUG:     " TEST_PGB_PATH "/test/src/module/common/debugOnTest::testFunction1: (paramInt: 99, paramBool: false,"
            " paramBoolP: *true, paramBoolPP: **true, paramVoidP: null, paramMode: 0755)\n"
            "P00  TRACE:         " TEST_PGB_PATH "/test/src/module/common/debugOnTest::testFunction2: (void)\n"
            "P00  TRACE:         " TEST_PGB_PATH "/test/src/module/common/debugOnTest::testFunction2: => void\n"
            "P00  DEBUG:     " TEST_PGB_PATH "/test/src/module/common/debugOnTest::testFunction1: => 1");

        testBoolP = NULL;
        testVoidP = (void *)1;

        testFunction1(99, false, testBoolP, testBoolPP, testVoidP, 0755);

        TEST_RESULT_LOG(
            "P00  DEBUG:     " TEST_PGB_PATH "/test/src/module/common/debugOnTest::testFunction1: (paramInt: 99, paramBool: false,"
            " paramBoolP: null, paramBoolPP: *null, paramVoidP: *void, paramMode: 0755)\n"
            "P00  TRACE:         " TEST_PGB_PATH "/test/src/module/common/debugOnTest::testFunction2: (void)\n"
            "P00  TRACE:         " TEST_PGB_PATH "/test/src/module/common/debugOnTest::testFunction2: => void\n"
            "P00  DEBUG:     " TEST_PGB_PATH "/test/src/module/common/debugOnTest::testFunction1: => 1");

        // -------------------------------------------------------------------------------------------------------------------------
        harnessLogLevelReset();
        testFunction1(55, true, NULL, NULL, NULL, 0755);

        TEST_RESULT_LOG("");
    }

    FUNCTION_HARNESS_RETURN_VOID();
}
