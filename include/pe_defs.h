#ifndef MDIE_PE_DEFS_H
#define MDIE_PE_DEFS_H

#define E_MAGIC              0x5A4D
#define IMAGE_NT_SIGNATURE   0x00004550

#define E_LFANEW_OFFSET      0x3C

#define PE32                 0x10B
#define PE32P                0x20B

#define IMAGE_SCN_CNT_CODE               0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080

#define IMAGE_SCN_MEM_EXECUTE            0x20000000
#define IMAGE_SCN_MEM_READ               0x40000000
#define IMAGE_SCN_MEM_WRITE              0x80000000

#endif