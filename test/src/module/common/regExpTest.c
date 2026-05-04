/***********************************************************************************************************************************
Test Regular Expression Handler
***********************************************************************************************************************************/
#include <regex.h>
#include <string.h>

/***********************************************************************************************************************************
Differential helper — runs the legacy POSIX `regcomp` / `regexec` engine on a pattern + haystack pair and reports the boolean match
result. Used to compare the Rust replacement against the previous C behaviour over thousands of random inputs.
***********************************************************************************************************************************/
static bool
legacy_regExpMatchOne(const char *const pattern, const char *const haystack)
{
    regex_t regex;

    if (regcomp(&regex, pattern, REG_EXTENDED) != 0)
        return false;

    const int execResult = regexec(&regex, haystack, 0, NULL, 0);
    regfree(&regex);

    return execResult == 0;
}

/***********************************************************************************************************************************
Test Run
***********************************************************************************************************************************/
static void
testRun(void)
{
    FUNCTION_HARNESS_VOID();

    // *****************************************************************************************************************************
    if (testBegin("regExpNew(), regExpMatch(), and regExpFree()"))
    {
        // The Rust implementation reports parse errors with the `regex` crate's diagnostic prefix; the legacy libc messages
        // (glibc / macOS / musl variants) are gone with the regcomp dependency.
        TEST_ERROR(
            regExpNew(STRDEF("[[[")), FormatError,
            "regex parse error:\n    [[[\n      ^\nerror: unclosed character class");
        TEST_ERROR(
            regExpNew(STRDEF("(unclosed")), FormatError,
            "regex parse error:\n    (unclosed\n    ^\nerror: unclosed group");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("new regexp");

        RegExp *regExp = NULL;
        TEST_ASSIGN(regExp, regExpNew(STRDEF("^abc")), "new regexp");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("regexp match");

        const String *string = STRDEF("abcdef");
        TEST_RESULT_BOOL(regExpMatch(regExp, string), true, "match regexp");
        TEST_RESULT_PTR(regExpMatchPtr(regExp, string), strZ(string), "check ptr");
        TEST_RESULT_STR_Z(regExpMatchStr(regExp, string), "abc", "check str");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("no regexp match");

        TEST_RESULT_BOOL(regExpMatch(regExp, STRDEF("bcdef")), false, "no match regexp");
        TEST_RESULT_PTR(regExpMatchPtr(regExp, STRDEF("bcdef")), NULL, "check ptr");
        TEST_RESULT_STR(regExpMatchStr(regExp, STRDEF("bcdef")), NULL, "check str");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("free regexp");

        TEST_RESULT_VOID(regExpFree(regExp), "free regexp");
    }

    // *****************************************************************************************************************************
    if (testBegin("regExpPrefix()"))
    {
        TEST_RESULT_STR(regExpPrefix(NULL), NULL, "null expression has no prefix");
        TEST_RESULT_STR(regExpPrefix(strNew()), NULL, "empty expression has no prefix");
        TEST_RESULT_STR(regExpPrefix(STRDEF("ABC")), NULL, "expression without begin anchor has no prefix");
        TEST_RESULT_STR(regExpPrefix(STRDEF("^.")), NULL, "expression with no regular character has no prefix");

        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABC$")), "ABC", "prefix stops at special character");
        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABC*")), "ABC", "prefix stops at special character");
        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABC+")), "ABC", "prefix stops at special character");
        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABC-")), "ABC", "prefix stops at special character");
        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABC?")), "ABC", "prefix stops at special character");
        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABC(")), "ABC", "prefix stops at special character");
        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABC[")), "ABC", "prefix stops at special character");
        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABC{")), "ABC", "prefix stops at special character");
        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABC ")), "ABC", "prefix stops at special character");
        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABC|")), "ABC", "prefix stops at special character");
        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABC\\")), "ABC", "prefix stops at special character");

        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABC^")), NULL, "no prefix when more than one begin anchor");
        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABC|^DEF")), NULL, "no prefix when more than one begin anchor");
        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABC[^DEF]")), "ABC", "prefix when ^ used for exclusion");
        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABC\\^DEF]")), "ABC", "prefix when ^ is escaped");

        TEST_RESULT_STR_Z(regExpPrefix(STRDEF("^ABCDEF")), "ABCDEF", "prefix is entire expression");
    }

    // *****************************************************************************************************************************
    if (testBegin("regExpMatchOne()"))
    {
        TEST_RESULT_BOOL(regExpMatchOne(STRDEF("^abc"), STRDEF("abcdef")), true, "match regexp");
        TEST_RESULT_BOOL(regExpMatchOne(STRDEF("^abc"), STRDEF("bcdef")), false, "no match regexp");
    }

    // *****************************************************************************************************************************
    if (testBegin("differential C/Rust match parity"))
    {
        // Patterns chosen so POSIX ERE leftmost-longest and the `regex` crate leftmost-first agree on whether *any* match exists.
        // pgBackRust uses these shapes for backup labels, archive filenames and option allow-lists; the boolean parity covers all
        // legacy callers because regExpMatch / regExpMatchOne return only booleans, and regExpMatchPtr / regExpMatchStr feed off
        // the same FFI primitive that locates the first match.
        const char *const patterns[] =
        {
            "^abc",
            "abc$",
            "^[0-9]+$",
            "^[A-Za-z_][A-Za-z0-9_]*$",
            "^[A-Z][A-Z0-9_-]*$",
            "(foo|bar|baz)",
            "^[^/]+$",
            "\\.tar\\.gz$",
            "^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
            "^pg_data/[^/]+\\.conf$",
        };

        // Deterministic LCG over a fixed seed — the same 12 000 inputs reproduce on every run, making divergence reproducible.
        // Each haystack is printable ASCII (32..127) of bounded length to dodge NUL bytes and odd locale interactions in libc.
        uint64_t state = UINT64_C(0x0123456789ABCDEF);
        char haystack[129];
        const unsigned int patternCount = LENGTH_OF(patterns);
        const unsigned int iterations = 12000;
        unsigned int comparisons = 0;

        for (unsigned int iter = 0; iter < iterations; iter++)
        {
            state = state * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
            const unsigned int patternIdx = (unsigned int)((state >> 32) % patternCount);
            const char *const pattern = patterns[patternIdx];

            state = state * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
            const size_t haystackLen = (size_t)((state >> 40) % 64);

            for (size_t b = 0; b < haystackLen; b++)
            {
                state = state * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
                haystack[b] = (char)(32 + (unsigned char)((state >> 56) % 96));
            }

            haystack[haystackLen] = '\0';

            const bool legacy = legacy_regExpMatchOne(pattern, haystack);
            const bool rust = regExpMatchOne(STR(pattern), STR(haystack));

            if (legacy != rust)
            {
                TEST_ERROR_FMT(
                    THROW_FMT(AssertError, "differential mismatch"),
                    AssertError,
                    "pattern=%s haystack=%s legacy=%d rust=%d",
                    pattern, haystack, legacy, rust);
            }

            comparisons++;
        }

        TEST_RESULT_UINT(comparisons, iterations, "all C/Rust differential comparisons agreed");
    }

    FUNCTION_HARNESS_RETURN_VOID();
}
