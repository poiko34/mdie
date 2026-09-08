#include <assert.h>
#include <stdio.h>

#include "pe/image.h"
#include "pe/utils.h"

static void test_rva_at_section_start(void)
{
    PE_SECTION_INFO section = {
        .virtual_address = 0x1000,
        .virtual_size = 0x2000,
        .pointer_to_raw_data = 0x400,
        .size_of_raw_data = 0x2000,
    };

    uint32_t offset;

    assert(rva_to_offset(&section, 1, 0x1000, &offset) == 1);
    assert(offset == 0x400);
}

static void test_rva_in_middle_of_section(void)
{
    PE_SECTION_INFO section = {
        .virtual_address = 0x1000,
        .virtual_size = 0x2000,
        .pointer_to_raw_data = 0x400,
        .size_of_raw_data = 0x2000,
    };

    uint32_t offset;

    assert(rva_to_offset(&section, 1, 0x1500, &offset) == 1);
    assert(offset == 0x900); /* 0x400 + (0x1500 - 0x1000) */
}

static void test_rva_outside_section(void)
{
    PE_SECTION_INFO section = {
        .virtual_address = 0x1000,
        .virtual_size = 0x2000,
        .pointer_to_raw_data = 0x400,
        .size_of_raw_data = 0x2000,
    };

    uint32_t offset;

    assert(rva_to_offset(&section, 1, 0x0FFF, &offset) == 0);
    assert(rva_to_offset(&section, 1, 0x3000, &offset) == 0);
}

static void test_zero_size_of_raw_data(void)
{
    /* Mirrors a .bss-style section: present in memory, absent in the file. */
    PE_SECTION_INFO section = {
        .virtual_address = 0x6000,
        .virtual_size = 0x00AC,
        .pointer_to_raw_data = 0,
        .size_of_raw_data = 0,
    };

    uint32_t offset;

    assert(rva_to_offset(&section, 1, 0x6000, &offset) == 0);
}

static void test_rva_in_virtual_padding_beyond_raw_data(void)
{
    PE_SECTION_INFO section = {
        .virtual_address = 0x1000,
        .virtual_size = 0x2000, /* virtual range extends beyond raw data */
        .pointer_to_raw_data = 0x400,
        .size_of_raw_data = 0x800, /* only the first 0x800 bytes exist in the file */
    };

    uint32_t offset;

    /* Still within raw data: valid file byte. */
    assert(rva_to_offset(&section, 1, 0x17FF, &offset) == 1);
    assert(offset == 0x400 + 0x7FF);

    /* Within VirtualSize but past SizeOfRawData: no real file byte. */
    assert(rva_to_offset(&section, 1, 0x1800, &offset) == 0);
    assert(rva_to_offset(&section, 1, 0x1FFF, &offset) == 0);
}

static void test_multiple_sections(void)
{
    PE_SECTION_INFO sections[3] = {
        {
            .virtual_address = 0x1000,
            .virtual_size = 0x1000,
            .pointer_to_raw_data = 0x400,
            .size_of_raw_data = 0x1000,
        },
        {
            .virtual_address = 0x2000,
            .virtual_size = 0x1000,
            .pointer_to_raw_data = 0x1400,
            .size_of_raw_data = 0x1000,
        },
        {
            .virtual_address = 0x3000,
            .virtual_size = 0x1000,
            .pointer_to_raw_data = 0x2400,
            .size_of_raw_data = 0x1000,
        },
    };

    uint32_t offset;

    assert(rva_to_offset(sections, 3, 0x1050, &offset) == 1);
    assert(offset == 0x450);

    assert(rva_to_offset(sections, 3, 0x2050, &offset) == 1);
    assert(offset == 0x1450);

    assert(rva_to_offset(sections, 3, 0x3FFF, &offset) == 1);
    assert(offset == 0x33FF); /* 0x2400 + (0x3FFF - 0x3000) */

    assert(rva_to_offset(sections, 3, 0x4000, &offset) == 0);
}

static void test_file_offset_overflow_guard(void)
{
    /* PointerToRawData + delta would exceed UINT32_MAX; must be rejected
     * rather than silently wrapping to a small, incorrect offset. */
    PE_SECTION_INFO section = {
        .virtual_address = 0x1000,
        .virtual_size = 0x20,
        .pointer_to_raw_data = 0xFFFFFFF0,
        .size_of_raw_data = 0x20,
    };

    uint32_t offset;

    assert(rva_to_offset(&section, 1, 0x1010, &offset) == 0);
}

static void test_checked_file_offsets(void)
{
    PE_SECTION_INFO section = {
        .virtual_address = 0x1000, .virtual_size = 0x200,
        .pointer_to_raw_data = 0x200, .size_of_raw_data = 0x200
    };
    uint32_t offset = 0;
    assert(rva_to_file_offset(&section, 1, 0x200, 0x400, 0x40, &offset));
    assert(offset == 0x40);
    assert(rva_to_file_offset(&section, 1, 0x200, 0x400, 0x11ff, &offset));
    assert(offset == 0x3ff);
    assert(!rva_to_file_offset(&section, 1, 0x200, 0x3ff, 0x11ff, &offset));
    assert(!rva_to_file_offset(&section, 1, 0x200, 0x20, 0x40, &offset));
    assert(!file_range_valid(UINT64_MAX, UINT64_MAX - 1, 4));
    assert(file_range_valid(1024, 512, 512));
    assert(!file_range_valid(1024, 512, 513));
}

static void test_little_endian_readers(void)
{
    FILE *file = tmpfile();
    assert(file);
    const unsigned char bytes[] = {
        0x34, 0x12, 0x78, 0x56, 0x34, 0x12,
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01
    };
    assert(fwrite(bytes, 1, sizeof(bytes), file) == sizeof(bytes));
    rewind(file);
    uint16_t a;
    uint32_t b;
    uint64_t c;
    assert(read_u16_le(file, &a) && a == 0x1234);
    assert(read_u32_le(file, &b) && b == 0x12345678);
    assert(read_u64_le(file, &c) && c == UINT64_C(0x0123456789abcdef));
    assert(!skip_bytes(file, 1));
    fclose(file);
}

int main(void)
{
    test_checked_file_offsets();
    test_little_endian_readers();
    test_rva_at_section_start();
    test_rva_in_middle_of_section();
    test_rva_outside_section();
    test_zero_size_of_raw_data();
    test_rva_in_virtual_padding_beyond_raw_data();
    test_multiple_sections();
    test_file_offset_overflow_guard();

    printf("All rva_to_offset tests passed.\n");

    return 0;
}
