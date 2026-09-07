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
  * Image Base
  * Section Alignment
  * File Alignment
  * Image Size
  * Header size

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

## Usage

Analyze a PE file using a positional argument:

```bash
./mdie app.exe
```

Or explicitly specify the file:

```bash
./mdie -f app.exe
```

Show the entropy map:

```bash
./mdie -g app.exe
```

The graph can also be enabled together with `-f`:

```bash
./mdie -f app.exe -g
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

```text
e_magic:         0x5A4D
e_lfanew:        0x00000080
Machine:         0x014C
Sections:        17
Timestamp:       0x5F3759DF
Characteristics: 0x0102
Optional Header: PE32
Linker version:  2.47
Entry Point:     0x00001460
Image Base:      0x0000000000400000
Section Align:   0x00001000
File Align:      0x00000200
Image Size:      0x00022000
Header Size:     0x00000400

Sections: 17

Name     RVA      VSize    RawSize  RawPtr   Entropy  Flags
-------- -------- -------- -------- -------- -------- ------
.text    00001000 00001990 00001A00 00000600 5.80     R-XC--
.data    00003000 00000038 00000200 00002000 0.57     RW--I-
.rdata   00004000 000005C4 00000600 00002200 4.97     R---I-
.bss     00006000 000000AC 00000000 00000000 0.00     RW---U
.idata   00007000 00000718 00000800 00003200 4.14     R---I-
.tls     00008000 00000008 00000200 00003A00 0.00     RW--I-
.reloc   00009000 00000244 00000400 00003C00 4.40     R---I-
```

With `-g` / `--graph`, `mdie` additionally displays an entropy map:

```text
Entropy map

        0.0                                            8.0
        ████████████████████████████████████████████████

.text   █████████████████████████████████████████████
.data   ███
.rdata  ███████████
.bss    █
.idata  ███████████
...
```

The entropy graph uses the actual raw bytes stored in each section. Each block represents a range of bytes from the section, and the block color corresponds to its Shannon entropy.

## Project structure

```text
mdie/
├── include/
│   ├── graph.h
│   ├── pe.h
│   ├── pe_defs.h
│   ├── pe_utils.h
│   └── print.h
├── src/
│   ├── graph.c
│   ├── main.c
│   ├── pe.c
│   ├── print.c
│   ├── sections.c
│   └── utils.c
├── test/
│   ├── Makefile
│   └── test32exe.c
├── LICENSE
├── Makefile
└── README.md
```

## Design

`mdie` is intentionally split into a few small components:

* `pe.c` — PE/COFF and Optional Header parsing
* `sections.c` — section table parsing
* `print.c` — human-readable PE information
* `utils.c` — shared PE utility functions
* `graph.c` — entropy map visualization
* `main.c` — CLI argument handling and program flow

Parsing and presentation are kept separate so that additional analysis modes can be added without making the core parser dependent on output formatting.

## Goals

The project is primarily educational: to understand the PE file format and build a small, focused PE parser from scratch on Linux.

The parser intentionally keeps the default output compact and focused on information that is useful during initial PE inspection.

Additional analysis features are implemented as optional CLI modes rather than making the default output unnecessarily verbose.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
