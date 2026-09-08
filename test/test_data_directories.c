#include <stdio.h>
#include <stdlib.h>

#include "pe.h"
#include "pe_defs.h"

static int tests_run = 0;
static int tests_failed = 0;

#define ASSERT_EQ(expected, actual) \
    do { \
        tests_run++; \
        if ((expected) != (actual)) { \
            fprintf( \
                stderr, \
                "FAIL: %s:%d: expected %zu, got %zu\n", \
                __FILE__, \
                __LINE__, \
                (size_t)(expected), \
                (size_t)(actual) \
            ); \
            tests_failed++; \
        } \
    } while (0)

static void test_pe32_full(void)
{
    PE_OPTIONAL_INFO optional = {
        .magic = PE32,
        .number_of_rva_and_sizes = 16
    };

    size_t result = get_available_data_directories(
        &optional,
        224
    );

    ASSERT_EQ(16, result);
}

static void test_pe32p_full(void)
{
    PE_OPTIONAL_INFO optional = {
        .magic = PE32P,
        .number_of_rva_and_sizes = 16
    };

    size_t result = get_available_data_directories(
        &optional,
        240
    );

    ASSERT_EQ(16, result);
}

static void test_pe32_no_directories(void)
{
    PE_OPTIONAL_INFO optional = {
        .magic = PE32,
        .number_of_rva_and_sizes = 16
    };

    size_t result = get_available_data_directories(
        &optional,
        96
    );

    ASSERT_EQ(0, result);
}

static void test_pe32p_no_directories(void)
{
    PE_OPTIONAL_INFO optional = {
        .magic = PE32P,
        .number_of_rva_and_sizes = 16
    };

    size_t result = get_available_data_directories(
        &optional,
        112
    );

    ASSERT_EQ(0, result);
}

static void test_pe32_partial(void)
{
    PE_OPTIONAL_INFO optional = {
        .magic = PE32,
        .number_of_rva_and_sizes = 16
    };

    size_t result = get_available_data_directories(
        &optional,
        96 + 5 * 8
    );

    ASSERT_EQ(5, result);
}

static void test_pe32p_partial(void)
{
    PE_OPTIONAL_INFO optional = {
        .magic = PE32P,
        .number_of_rva_and_sizes = 16
    };

    size_t result = get_available_data_directories(
        &optional,
        112 + 3 * 8
    );

    ASSERT_EQ(3, result);
}

static void test_pe32_too_small(void)
{
    PE_OPTIONAL_INFO optional = {
        .magic = PE32,
        .number_of_rva_and_sizes = 16
    };

    size_t result = get_available_data_directories(
        &optional,
        95
    );

    ASSERT_EQ(0, result);
}

static void test_pe32p_too_small(void)
{
    PE_OPTIONAL_INFO optional = {
        .magic = PE32P,
        .number_of_rva_and_sizes = 16
    };

    size_t result = get_available_data_directories(
        &optional,
        111
    );

    ASSERT_EQ(0, result);
}

static void test_ignores_declared_count(void)
{
    PE_OPTIONAL_INFO optional = {
        .magic = PE32,
        .number_of_rva_and_sizes = 1
    };

    size_t result = get_available_data_directories(
        &optional,
        96 + 5 * 8
    );

    ASSERT_EQ(5, result);
}

int main(void)
{
    test_pe32_full();
    test_pe32p_full();

    test_pe32_no_directories();
    test_pe32p_no_directories();

    test_pe32_partial();
    test_pe32p_partial();

    test_pe32_too_small();
    test_pe32p_too_small();

    test_ignores_declared_count();

    printf(
        "Tests run: %d, failed: %d\n",
        tests_run,
        tests_failed
    );

    return tests_failed != 0;
}