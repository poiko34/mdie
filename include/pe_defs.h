#ifndef MDIE_PE_DEFS_H
#define MDIE_PE_DEFS_H

/* DOS / PE signatures */
#define E_MAGIC            0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550

/* DOS header offsets */
#define E_LFANEW_OFFSET    0x3C

/* Optional Header magic */
#define PE32               0x10B
#define PE32P              0x20B

/* Minimum standard-fields size of each Optional Header variant,
 * i.e. without data directories. */
#define PE32_OPTIONAL_HEADER_MIN_SIZE  96
#define PE32P_OPTIONAL_HEADER_MIN_SIZE 112

/* Data directories */
#define PE_MAX_DATA_DIRECTORIES        16
#define IMAGE_DIRECTORY_ENTRY_SECURITY 4

/* Section characteristics */
#define IMAGE_SCN_CNT_CODE               0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080

#define IMAGE_SCN_MEM_EXECUTE            0x20000000
#define IMAGE_SCN_MEM_READ               0x40000000
#define IMAGE_SCN_MEM_WRITE              0x80000000

#endif
