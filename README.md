# mdie

A small Linux CLI PE analyzer inspired by [Detect It Easy](https://github.com/horsicq/Detect-It-Easy).

`mdie` is a lightweight command-line tool for inspecting the basic structure of Windows Portable Executable (PE) files without relying on Windows-specific headers or APIs.

## Features

* DOS header information
  * `e_magic`
  * `e_lfanew`

* PE/COFF file header
  * Machine
  * Number of sections
  * Timestamp
  * Characteristics

* Optional Header
  * PE32 / PE32+
  * Linker version
  * Entry Point
  * Entry Point file offset
  * Image Base
  * Section Alignment
  * File Alignment
  * Image Size
  * Header size

* Data Directories
  * Export Table
  * Import Table
  * Resource Table
  * Exception Table
  * Certificate Table
  * Base Relocation Table
  * Debug
  * Architecture
  * Global Ptr
  * TLS Table
  * Load Config Table
  * Bound Import
  * Import Address Table (IAT)
  * Delay Import Descriptor
  * CLR Runtime Header
  * Optional display with `-d, --directories`
  * Handles truncated data directory tables

* Section table
  * Section name
  * RVA
  * Virtual size
  * Raw size
  * Raw file offset
  * Section characteristics / flags
  * Entropy

* Entropy map
  * Per-section entropy visualization
  * Adaptive graph width based on terminal size
  * Entropy represented as a color gradient from low to high entropy

* Command-line interface
  * Positional input file
  * `-f, --file`
  * `-d, --directories`
  * `-g, --graph`
  * `-v, --version`
  * `-h, --help`

* Native Linux implementation in C

* No dependency on `windows.h`

## Build

Requirements:

* GCC or Clang
* GNU Make
* A Linux environment

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

## Test

The `test/` directory contains a minimal Windows PE32 executable used to test `mdie`.

Build the test executable:

```bash
cd test
make
```

This produces:

```text
test32.exe
```

Run `mdie` against it from the project root:

```bash
./mdie test/test32.exe
```

The test executable is built with the MinGW 32-bit cross-compiler:

```text
i686-w64-mingw32-gcc
```

Clean the test build:

```bash
cd test
make clean
```

The project also contains standalone unit tests for PE utility functions.

Run all unit tests from the project root:

```bash
make test
```

## Usage

Analyze a PE file using a positional argument:

```bash
./mdie app.exe
```

Or explicitly specify the file:

```bash
./mdie -f app.exe
```

Show the PE data directory table:

```bash
./mdie -d app.exe
```

Data directories are hidden by default to keep the normal output compact.

Show the entropy map:

```bash
./mdie -g app.exe
```

The graph can also be enabled together with `-f`:

```bash
./mdie -f app.exe -g
```

Data directories and the entropy map can be displayed together:

```bash
./mdie -d -g app.exe
```

Show help:

```bash
./mdie --help
```

Show version:

```bash
./mdie --version
```

## Example output

A normal invocation displays the basic PE structure:

```text
e_magic:         0x5A4D
e_lfanew:        0x00000078
Machine:         0x8664
Sections:        4
Timestamp:       0x6A9E87B9
Characteristics: 0x0022
Optional Header: PE32+
Linker version:  14.00
Entry Point:     0x00001180
EP File Offset:  0x00000580
Image Base:      0x0000000140000000
Section Align:   0x00001000
File Align:      0x00000200
Image Size:      0x0000F000
Header Size:     0x00000400

Sections: 4

Name     RVA      VSize    RawSize  RawPtr   Entropy  Flags 
-------- -------- -------- -------- -------- -------- ------
.text    00001000 000073B6 00007400 00000400 6.49     R-XC--
.rdata   00009000 0000040C 00000600 00007800 3.56     R---I-
.data    0000A000 00003EA0 00001800 00007E00 6.61     RW--I-
.pdata   0000E000 000001EC 00000200 00009600 3.80     R---I-
```

With `-d` / `--directories`, `mdie` additionally displays the PE Data Directory table:

```text
Data Directories:

Name                     RVA/Offset  Size
------------------------ ----------- ----------
Export Table             N/A
Import Table             0x00009070  0x0000003C
Resource Table           N/A
Exception Table          0x0000E000  0x000001EC
Certificate Table        N/A
Base Relocation Table    N/A
Debug                    N/A
Architecture             N/A
Global Ptr               N/A
TLS Table                N/A
Load Config Table        N/A
Bound Import             N/A
IAT                      0x00009108  0x00000058
Delay Import Descriptor  N/A
CLR Runtime Header       N/A
Reserved                 N/A
```

The Data Directory table is parsed according to the PE Optional Header size and the declared `NumberOfRvaAndSizes` value.

The Certificate Table is handled as a special case because its `VirtualAddress` field represents a file offset rather than an RVA.

If the declared number of directories is larger than the number physically available in the Optional Header, `mdie` limits parsing to the available entries and reports a warning when directory output is requested.

With `-g` / `--graph`, `mdie` additionally displays an entropy map:

```text
Entropy map

        0.0                                                                 8.0
        ████████████████████████████████████████████████████████████████████

.text   ████████████████████████████████████████████████████████████████████
.rdata  ███████████████████████████████████████████████████████████████████
.data   ████████████████████████████████████████████████████████████████████
.pdata  ████████████████████████████████
```

The entropy graph uses the actual raw bytes stored in each section. Each block represents a range of bytes from the section, and the block color corresponds to its Shannon entropy.

## Project structure

```text
.
├── include/
│   ├── defs.h
│   ├── graph.h
│   ├── pe_defs.h
│   ├── pe.h
│   ├── pe_utils.h
│   └── print.h
│
├── src/
│   ├── graph.c
│   ├── main.c
│   ├── pe.c
│   ├── print.c
│   ├── sections.c
│   └── utils.c
│
├── test/
│   ├── Makefile
│   ├── test32exe.c
│   ├── test_data_directories.c
│   └── test_rva_to_offset.c
│
├── LICENSE
├── Makefile
└── README.md
```

## Main components

* `include/` — public headers and PE definitions
* `src/pe.c` — PE/COFF, Optional Header, and Data Directory parsing
* `src/sections.c` — section table parsing
* `src/print.c` — human-readable PE information
* `src/utils.c` — shared PE utility functions
* `src/graph.c` — entropy map visualization
* `src/main.c` — CLI argument handling and program flow
* `test/test32exe.c` — source for the test PE32 executable
* `test/test_rva_to_offset.c` — unit tests for RVA-to-file-offset conversion
* `test/test_data_directories.c` — unit tests for Data Directory parsing

## Design

`mdie` is intentionally split into a few small components:

* `pe.c` — PE/COFF, Optional Header, and Data Directory parsing
* `sections.c` — section table parsing
* `print.c` — human-readable PE information
* `utils.c` — shared PE utility functions
* `graph.c` — entropy map visualization
* `main.c` — CLI argument handling and program flow

Parsing and presentation are kept separate so that additional analysis modes can be added without making the core parser dependent on output formatting.

Data Directory parsing respects the declared `SizeOfOptionalHeader` and `NumberOfRvaAndSizes` values, preventing reads beyond the available Optional Header data.

## Goals

The project is primarily educational: to understand the PE file format and build a small, focused PE parser from scratch on Linux.

The parser intentionally keeps the default output compact and focused on information that is useful during initial PE inspection.

Additional analysis features are implemented as optional CLI modes rather than making the default output unnecessarily verbose. For example, PE Data Directories and the entropy map are available through dedicated command-line options.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.