#include <stdint.h>
#include "cli/ui.h"
#include "pe/constants.h"

void format_section_name(const char name[8], char output[9])
{
    size_t i = 0;
    for (; i < 8 && name[i]; ++i) {
        unsigned char c = (unsigned char)name[i];
        output[i] = c >= 32 && c <= 126 ? (char)c : '?';
    }
    output[i] = '\0';
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
