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

* Imports / IAT (`-i, --import`)
  * DLL and function names, hints and ordinal imports
  * IAT slot RVA, file offset and stored value
  * PE32 and PE32+, with `FirstThunk` fallback
  * Bound IAT values remain distinct from lookup-table names

* Build-tool summary by default; details with `-c, --compiler`
  * Separate compiler, toolchain, linker and runtime candidates
  * Confidence labels and supporting evidence
  * Rich Header structure/checksum validation
  * Embedded GCC, Clang, MSVC, MinGW and linker marker rules
  * CLR metadata and modern Go build-info recognition

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
  * `-H, --headers`
* `-i, --import`
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

Run all unit tests and CLI regression tests from the project root (Python 3 is required for the CLI tests):

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

Show ordinary imports and their Import Address Table (IAT) slots:

```bash
./mdie -i app.exe
./mdie --import app.exe
./mdie -i -d -g app.exe
```

Imports are grouped by DLL. Each row contains the slot's RVA, file offset,
stored IAT value, hint (or `#ordinal`) and function name. Names come from the
Import Lookup Table (`OriginalFirstThunk`); `FirstThunk` is used when that
lookup table is absent. Stored IAT values are file contents, not addresses
resolved in a running process. For bound imports without a lookup table,
names are reported as unavailable rather than interpreting bound addresses as RVAs.

This mode parses the ordinary Import Directory (index 1), following each
DLL's `FirstThunk` to its IAT slots. It does not require a separate IAT Data
Directory (index 12), load DLLs, resolve runtime addresses or enumerate delay imports.
Malformed import data produces warnings and exit code `2`; partial rows may
still be shown. Analysis is capped at 4096 DLL descriptors, 65536 entries,
256-byte DLL names and 1024-byte function names; reaching a limit is reported.
Strings are sanitized for terminal output.

Format reference: [Microsoft PE format — imports](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-directory-table).

Normal output includes three compact lines: `Compiler`, `Linker` and `Runtime`.
Candidates retain `likely` / `possible` labels; ambiguous results remain unknown.
Use `-c` / `--compiler` to replace that summary with the detailed report and evidence:


```bash
./mdie -c app.exe
./mdie --compiler app.exe
./mdie -c -i -d -g app.exe
```

This is an initial heuristic detector, not a compiler-identification guarantee.
The detailed report's `low` / `medium` / `high` labels describe evidence strength, not calibrated
probabilities. Conflicting producer markers are reported as mixed evidence.
Exact toolchain versions are not inferred from the Optional Header linker
version. The Go inline build-info version is displayed when decoded.

| Evidence | Interpretation and limits |
| --- | --- |
| GCC/Clang/MSVC producer text in section raw data | Compiler candidate; text may come from a dependency or arbitrary data. |
| MinGW runtime/symbol text + GCC/Clang marker | MinGW-compatible combination; exact LLVM-MinGW distribution remains unconfirmed. |
| `llvm-mingw` text | Low-confidence distribution hint only. |
| Rich/DanS with valid record layout and checksum | Microsoft-compatible build artifacts and LINK-compatible candidate; does not identify the compiler. Product IDs are not mapped in this version. |
| LLD/GNU ld identifier text | Low-confidence linker candidate. Many PE linkers leave no such identifier; `unknown` is expected. The LLD `.comment` convention is primarily an ELF convention, not a guaranteed PE artifact. |
| CLR header + BSJB metadata root/version | .NET/CLR metadata; does not distinguish C#, VB.NET or other languages and does not validate all metadata streams. |
| Aligned Go build-info header with inline `go1.*` version | Go build-info evidence. Legacy pointer layouts are a low-confidence hint; devel versions are not decoded. |

Detection runs by default and scans at most 16 MiB of section raw data in file-section order.
It excludes overlays and does not fetch PDBs or parse DWARF/CodeView records;
producer strings are matched as embedded artifacts. Rich inspection is limited
to DOS areas up to 64 KiB and at most 32 Rich-marker candidates. A scan limit,
unreadable range or invalid declared CLR metadata is reported as incomplete
and gives exit status `2`. An invalid Rich marker is ignored and listed as evidence.
Rust and Delphi do not yet have dedicated detection rules. Stripped, packed,
obfuscated or mixed-toolchain files may remain unknown or ambiguous.

References: [Microsoft metadata](https://learn.microsoft.com/en-us/dotnet/standard/metadata-and-self-describing-components),
[Go build-info implementation](https://go.dev/src/debug/buildinfo/buildinfo.go),
[LIEF Rich Header reference](https://lief.re/doc/stable/doxygen/classLIEF_1_1PE_1_1RichHeader.html),
[LLVM linker documentation](https://lld.llvm.org/).

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

## CLI layout

Normal output is organized into a file banner, **Overview**, **Build tools**
and **Sections**. Architecture and subsystem fields are decoded into names.
Addresses remain in hex. Header internals are available explicitly:

```bash
./mdie app.exe                  # compact grouped report
./mdie -H app.exe               # add raw PE headers
./mdie --headers -i -g app.exe  # headers, imports and entropy
```

`-H` / `--headers` includes DOS signatures/offsets, COFF fields, timestamp,
linker version, alignments and header sizes. `-c` still replaces the compact
build-tool summary with detailed evidence. Other flags add clearly titled
blocks after the section table. Section tables use a stacked layout below
72 terminal columns; imports use stacked entries below 100 columns.

Headings use ANSI color only on a terminal. Set `NO_COLOR=1` or `TERM=dumb`
to disable colors, including the entropy map. Redirected reports contain no
ANSI styling. Displayed filenames are sanitized and shortened to fit the banner.

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

If the declared number of directories exceeds the space declared in the Optional Header, `mdie` limits parsing to the available entries and reports a warning, including without `-d`. Physically truncated headers and section tables are rejected.

With `-g` / `--graph`, `mdie` additionally displays a color entropy map.

Each section gets a full-width bar from 0% to 100% of its raw bytes, with its raw size and whole-section entropy (`H/8`) alongside. Bar lengths are normalized per section; they do not compare section sizes.

Local entropy is measured in fixed 1024-byte windows, including the shorter final window. Display cells use the byte-overlap-weighted mean of these window estimates. Small sections stretch their measured values across the bar; they are never divided into tiny samples just to fill the terminal. Resizing changes display grouping, not the underlying analysis windows. The whole-section value can differ from local window values.

Blue means low entropy; green/yellow intermediate; red high. Without a terminal, with `NO_COLOR` set, or with `TERM=dumb`, a density ramp (`.:-=+*#%@`) replaces ANSI colors. `*` next to the numeric value marks a section shorter than 1 KiB: its estimate has less evidence and is limited by sample size. `?` marks unreadable data. Empty raw sections are labeled explicitly. High entropy alone does not determine whether a file is packed or malicious.

## Validation and exit status

* `0`: analysis completed without the implemented validation warnings.
* `1`: input/usage error, unreadable or truncated required headers, or allocation failure.
* `2`: report produced, but a declared directory count, raw section range, header size, entry point or requested import analysis failed validation.

Raw section ranges are checked against the actual file size. Entry-point offsets are checked against EOF and can resolve into headers. A zero entry-point RVA is displayed as having no entry-point file offset. Non-printable section-name bytes are replaced with `?` in both output modes.

Serialized integer fields are decoded explicitly as little-endian values rather than reading host structures. File positioning uses C `long` (`fseek`/`ftell`); large-file support therefore depends on the host's `long` range. Passing these checks does not guarantee that Windows will load the image.

## Project structure

```text
.
├── include/
│   ├── defs.h
│   ├── ui.h
│   ├── compiler.h
│   ├── imports.h
│   ├── graph.h
│   ├── pe_defs.h
│   ├── pe.h
│   ├── pe_utils.h
│   └── print.h
│
├── src/
│   ├── ui.c
│   ├── compiler.c
│   ├── imports.c
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
│   ├── test_rva_to_offset.c
│   ├── test_cli.py
│   ├── test_imports.py
│   └── test_compiler.py
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
* `src/ui.c` — shared terminal headings, color policy and file banner
* `src/compiler.c` — build-tool evidence collection and reporting
* `src/imports.c` — bounded import/IAT parsing with visitor callbacks
* `src/graph.c` — entropy map visualization
* `src/main.c` — CLI argument handling and program flow
* `test/test32exe.c` — source for the test PE32 executable
* `test/test_rva_to_offset.c` — unit tests for RVA-to-file-offset conversion
* `test/test_data_directories.c` — unit tests for Data Directory parsing
* `test/test_cli.py` — generated PE32/PE32+ fixtures and CLI regression tests
* `test/test_compiler.py` — build-tool positive, negative, mixed and bounded-scan tests
* `test/test_imports.py` — import/IAT regression tests

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