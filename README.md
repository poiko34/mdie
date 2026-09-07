# mdie

A small Linux CLI PE analyzer inspired by [Detect It Easy](https://github.com/horsicq/Detect-It-Easy).

`mdie` is a lightweight command-line tool for inspecting the basic structure of Windows Portable Executable (PE) files without relying on Windows-specific headers or APIs.

## Features

- DOS header information
  - `e_magic`
  - `e_lfanew`
- PE/COFF file header
  - Machine
  - Number of sections
- Optional Header
  - PE32 / PE32+
  - Linker version
  - Entry Point
  - Image Base
  - Section Alignment
  - File Alignment
  - Image Size
- Section table
  - Section name
  - RVA
  - Virtual size
  - Raw size
  - Raw file offset
  - Section characteristics / flags
- Native Linux implementation in C
- No dependency on `windows.h`

## Build

Requirements:

- GCC or Clang
- GNU Make
- A Linux environment

Build the project with:

```bash
make
```

The resulting executable is:

```text
./mdie
```

To remove build artifacts:

```bash
make clean
```

## Usage

```bash
./mdie <file>
```

Example:

```bash
./mdie app.exe
```

Example output:

```text
e_magic:         0x5A4D
e_lfanew:        0x00000078
Machine:         0x8664
Sections:        4
Optional Header: PE32+
Linker version:  14.00
Entry Point:     0x00001180
Image Base:      0x0000000140000000
Section Align:   0x00001000
File Align:      0x00000200
Image Size:      0x0000F000

Sections: 4

Name     RVA      VSize    RawSize  RawPtr   Flags
-------- -------- -------- -------- -------- ------
.text    00001000 000073B6 00007400 00000400 R-XC--
.rdata   00009000 0000040C 00000600 00007800 R---I-
.data    0000A000 00003EA0 00001800 00007E00 RW--I-
.pdata   0000E000 000001EC 00000200 00009600 R---I-
```

## Project structure

```text
mdie/
├── include/
│   ├── pe.h
│   ├── pe_defs.h
│   ├── pe_utils.h
│   └── print.h
├── src/
│   ├── main.c
│   ├── pe.c
│   ├── print.c
│   ├── sections.c
│   └── utils.c
├── test/
│   └── test32exe.c
├── LICENSE
├── Makefile
└── README.md
```

## Goals

The project is primarily educational: to understand the PE file format and build a small, focused PE parser from scratch on Linux.

The parser intentionally keeps the output compact and focused on information that is useful during initial PE inspection.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
