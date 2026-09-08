#include <stdio.h>
#include <stdlib.h>

#include "pe/image.h"
#include "pe/constants.h"

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

static void write_u32_le(FILE *file, uint32_t value)
{
    unsigned char bytes[4];
    for (size_t i = 0; i < 4; ++i) bytes[i] = (unsigned char)(value >> (i * 8));
    if (fwrite(bytes, 1, sizeof(bytes), file) != sizeof(bytes)) {
        fprintf(stderr, "Cannot write test fixture.\n");
        exit(EXIT_FAILURE);
    }
}

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

static void test_reads_directories(void)
{
    FILE *file = tmpfile();

    if (!file) {
        fprintf(stderr, "FAIL: %s:%d: tmpfile() failed\n",
                __FILE__, __LINE__);
        tests_failed++;
        return;
    }

    PE_OPTIONAL_INFO optional = {
        .magic = PE32,
        .number_of_rva_and_sizes = 2
    };

    const long optional_header_offset = 100;
    const uint16_t optional_header_size = 96 + 2 * 8;

    fseek(file, optional_header_offset + 96, SEEK_SET);

    uint32_t rva0 = 0x12345678;
    uint32_t size0 = 0x100;
    uint32_t rva1 = 0x87654321;
    uint32_t size1 = 0x200;

    write_u32_le(file, rva0);
    write_u32_le(file, size0);
    write_u32_le(file, rva1);
    write_u32_le(file, size1);

    PE_DATA_DIRECTORY directories[PE_MAX_DATA_DIRECTORIES] = {0};

    size_t count = read_data_directories(
        file,
        &optional,
        optional_header_offset,
        optional_header_size,
        directories
    );

    ASSERT_EQ(2, count);

    ASSERT_EQ(0x12345678, directories[0].virtual_address);
    ASSERT_EQ(0x100, directories[0].size);

    ASSERT_EQ(0x87654321, directories[1].virtual_address);
    ASSERT_EQ(0x200, directories[1].size);

    fclose(file);
}

static void test_read_does_not_exceed_available_entries(void)
{
    FILE *file = tmpfile();

    if (!file) {
        fprintf(stderr, "FAIL: %s:%d: tmpfile() failed\n",
                __FILE__, __LINE__);
        tests_failed++;
        return;
    }

    PE_OPTIONAL_INFO optional = {
        .magic = PE32,
        .number_of_rva_and_sizes = 16
    };

    const long optional_header_offset = 100;
    const uint16_t optional_header_size = 96 + 2 * 8;

    fseek(file, optional_header_offset + 96, SEEK_SET);

    uint32_t rva0 = 0x11111111;
    uint32_t size0 = 0x100;
    uint32_t rva1 = 0x22222222;
    uint32_t size1 = 0x200;

    write_u32_le(file, rva0);
    write_u32_le(file, size0);
    write_u32_le(file, rva1);
    write_u32_le(file, size1);

    PE_DATA_DIRECTORY directories[PE_MAX_DATA_DIRECTORIES] = {0};

    size_t count = read_data_directories(
        file,
        &optional,
        optional_header_offset,
        optional_header_size,
        directories
    );

    ASSERT_EQ(2, count);

    ASSERT_EQ(0x11111111, directories[0].virtual_address);
    ASSERT_EQ(0x100, directories[0].size);

    ASSERT_EQ(0x22222222, directories[1].virtual_address);
    ASSERT_EQ(0x200, directories[1].size);

    fclose(file);
}

static void test_read_truncated_file(void)
{
    FILE *file = tmpfile();

    if (!file) {
        fprintf(stderr, "FAIL: %s:%d: tmpfile() failed\n",
                __FILE__, __LINE__);
        tests_failed++;
        return;
    }

    PE_OPTIONAL_INFO optional = {
        .magic = PE32,
        .number_of_rva_and_sizes = 2
    };

    const long optional_header_offset = 100;
    const uint16_t optional_header_size = 96 + 2 * 8;

    fseek(file, optional_header_offset + 96, SEEK_SET);

    uint32_t rva = 0x12345678;
    uint32_t size = 0x100;

    write_u32_le(file, rva);
    write_u32_le(file, size);

    PE_DATA_DIRECTORY directories[PE_MAX_DATA_DIRECTORIES] = {0};

    size_t count = read_data_directories(
        file,
        &optional,
        optional_header_offset,
        optional_header_size,
        directories
    );

    ASSERT_EQ(1, count);

    ASSERT_EQ(0x12345678, directories[0].virtual_address);
    ASSERT_EQ(0x100, directories[0].size);

    fclose(file);
}

static void test_read_pe32p_directories(void)
{
    FILE *file = tmpfile();

    if (!file) {
        fprintf(stderr, "FAIL: %s:%d: tmpfile() failed\n",
                __FILE__, __LINE__);
        tests_failed++;
        return;
    }

    PE_OPTIONAL_INFO optional = {
        .magic = PE32P,
        .number_of_rva_and_sizes = 2
    };

    const long optional_header_offset = 100;
    const uint16_t optional_header_size = 112 + 2 * 8;

    fseek(file, optional_header_offset + 112, SEEK_SET);

    uint32_t rva0 = 0x11111111;
    uint32_t size0 = 0x100;
    uint32_t rva1 = 0x22222222;
    uint32_t size1 = 0x200;

    write_u32_le(file, rva0);
    write_u32_le(file, size0);
    write_u32_le(file, rva1);
    write_u32_le(file, size1);

    PE_DATA_DIRECTORY directories[PE_MAX_DATA_DIRECTORIES] = {0};

    size_t count = read_data_directories(
        file,
        &optional,
        optional_header_offset,
        optional_header_size,
        directories
    );

    ASSERT_EQ(2, count);

    ASSERT_EQ(0x11111111, directories[0].virtual_address);
    ASSERT_EQ(0x100, directories[0].size);

    ASSERT_EQ(0x22222222, directories[1].virtual_address);
    ASSERT_EQ(0x200, directories[1].size);

    fclose(file);
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
    test_reads_directories();

    test_read_does_not_exceed_available_entries();
    test_read_truncated_file();

    test_read_pe32p_directories();

    printf(
        "Tests run: %d, failed: %d\n",
        tests_run,
        tests_failed
    );

    return tests_failed != 0;
}