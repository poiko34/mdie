#include "pe_utils.h"
#include "pe_defs.h"

int skip_bytes(FILE *file, size_t n)
{
    return fseek(file, (long)n, SEEK_CUR) == 0;
}

void get_section_perms(uint32_t ch, char *perm_str)
{
    perm_str[0] = (ch & IMAGE_SCN_MEM_READ) ? 'R' : '-';
    perm_str[1] = (ch & IMAGE_SCN_MEM_WRITE) ? 'W' : '-';
    perm_str[2] = (ch & IMAGE_SCN_MEM_EXECUTE) ? 'X' : '-';
    perm_str[3] = (ch & IMAGE_SCN_CNT_CODE) ? 'C' : '-';
    perm_str[4] = (ch & IMAGE_SCN_CNT_INITIALIZED_DATA) ? 'I' : '-';
    perm_str[5] = (ch & IMAGE_SCN_CNT_UNINITIALIZED_DATA) ? 'U' : '-';
    perm_str[6] = '\0';
}