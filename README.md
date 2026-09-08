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

* Exports / EAT (`-e, --export`)
  * Named and ordinal-only exports, aliases and unused EAT slots
  * Public ordinal, EAT slot RVA, target RVA and file offset
  * Forwarder strings, including `DLL.#ordinal`
  * PE32/PE32+ (EAT entries remain 32-bit RVAs)

* Debug Directory / CodeView (`--debug`)
  * Debug entry type names and numeric values for PE32 and PE32+
  * RSDS: GUID, age and PDB path
  * NB10: timestamp, age and PDB path
  * File-bound checks, overlay payloads and bounded PDB strings

* Resources (`-r, --resources`)
  * PE32/PE32+ tree: type, name/ID and language
  * Standard `RT_*` type names, payload size, RVA and file offset
  * `RT_VERSION`: fixed and localized version fields
  * `RT_MANIFEST`: bounded Unicode text with terminal controls escaped

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
  * `--debug`
  * `-r, --resources`
  * `-e, --export`
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

Show exports and Export Address Table (EAT) slots:

```bash
./mdie -e library.dll
./mdie --export library.dll
./mdie -e -i -d -g library.dll
```

The public ordinal is `OrdinalBase + EAT index`. Name ordinals are unbiased
indexes, not public ordinals. Multiple names for one slot are shown separately;
zero-valued EAT holes are omitted. A target RVA inside the Export Directory is
a forwarder string, bounded by that directory. The tool displays forwarders
without loading the target DLL. Exported data without a file-backed byte has
file offset `N/A`. Malformed tables produce warnings and exit code `2`.
Limits: 65536 EAT slots and names, 1024 bytes per module/name/forwarder string.

Reference: [Microsoft export tables](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-directory-table).

Show Debug Directory entries and CodeView PDB references:

```bash
./mdie --debug app.exe
./mdie --debug -H -i -e -d app.exe
```

`--debug` parses Data Directory index 6 as an array of 28-byte entries for
both PE32 and PE32+. Each entry shows its type name and numeric value,
payload size, RVA and file offset. CodeView entries (type 2) additionally show:

* `RSDS`: GUID in canonical GUID byte order, decimal age and PDB path.
* `NB10`: the CodeView timestamp in hexadecimal, decimal age and PDB path.
  This timestamp comes from the NB10 payload, not the Debug Directory entry.

The directory is resolved through RVAs, including header storage. Payloads
are read using `PointerToRawData`, a file offset, so PDB references in overlays
are supported even when `AddressOfRawData` is zero. The latter is displayed as
metadata; it is not used as a fallback or cross-checked against the file pointer.
Nonempty payloads require a nonzero file pointer and a range contained in the file.

PDB paths must have a NUL terminator inside `SizeOfData`; empty paths are shown
as `<empty>`. Non-printable and non-ASCII path bytes are displayed as `?`.
Limits are 4096 directory entries and 4096 path bytes excluding the terminator.
Invalid ranges, truncated records/headers, missing string terminators and exceeded
limits produce warnings and exit status `2`. Complete entries before a truncated
record remain visible; an invalid payload does not prevent later entries from
being reported. A directory size not divisible by 28 is reported as malformed,
while its complete entries are still inspected.

Unknown debug types retain their numeric value. Unsupported CodeView signatures
are shown in hexadecimal without decoding their contents; they alone do not
cause validation failure. Other debug payload formats and external PDB files
are not parsed or fetched. Without `--debug`, this additional analysis is disabled.

References: [Microsoft Debug Directory](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-directory-image-only),
[Crashpad RSDS layout](https://crashpad.chromium.org/doxygen/structcrashpad_1_1CodeViewRecordPDB70.html),
[Crashpad NB10 layout](https://crashpad.chromium.org/doxygen/structcrashpad_1_1CodeViewRecordPDB20.html).

Show the resource tree, version information and manifests:

```bash
./mdie -r app.exe
./mdie --resources -H -d --debug app.exe
```

The resource tree uses Data Directory index 2 and three levels: type, name/ID,
and language. Numeric types are labeled with standard names such as `RT_VERSION`,
`RT_ICON`, `RT_GROUP_ICON`, `RT_MANIFEST`, `RT_STRING` and `RT_RCDATA`.
Custom numeric types retain their IDs; named types and resource names are decoded
from length-prefixed UTF-16LE. Language IDs are displayed in hexadecimal.
Each leaf shows its size in bytes, payload RVA, file offset of its first byte
(or `N/A`), and code page. Opaque resource contents, including icons, string tables
and RCDATA, are not decoded in this version.

For numeric `RT_VERSION` entries, the report shows `FileVersion` and
`ProductVersion` from `VS_FIXEDFILEINFO`, labeled `[fixed]`. It also shows
`FileVersion`, `ProductVersion`, `CompanyName`, `FileDescription` and
`OriginalFilename` when present in `StringFileInfo`. String values are labeled
with their eight-digit language/codepage table key (for example `[040904B0]`),
so multiple translations and resource languages remain distinct. Fixed and
localized version values are reported separately; missing fields are omitted.

Numeric `RT_MANIFEST` entries are displayed as text. Supported encodings are
UTF-8 (with or without BOM), UTF-16LE/BE with BOM, and BOM-less UTF-16 beginning
with `<`. XML is not parsed, validated or resolved; external references are not
opened. Printable Unicode is preserved. Terminal control characters, bidi
controls and selected invisible formatting characters are escaped as `\uXXXX`;
only manifest newlines affect layout. CRLF is normalized, lines are indented and
long manifest lines wrap to the display width. An embedded NUL is escaped rather
than ending the preview. Other character encodings are not decoded.

Directory offsets are relative to the Resource Directory base; data entry RVAs
are image-relative and may point outside the directory. Full declared directory
and payload ranges must be backed by file bytes, including across section
boundaries. Overflowing ranges, missing raw storage, invalid UTF-16/surrogate
pairs, cycles, premature leaves and directories below the language level are
reported as malformed. VERSIONINFO block lengths, alignment, value lengths and
string terminators are checked. Available siblings remain visible after a bad
branch or payload; an unreadable table stops that branch.

Resource analysis and output are bounded by these limits:

| Limit | Value |
| --- | --- |
| Resource tree entries, across the entire traversal | 1024 |
| Resource tree depth | 3 levels: type, name/ID, language |
| Resource name | 256 UTF-16 code units |
| VERSIONINFO resource | 65536 bytes |
| VERSIONINFO blocks / depth | 256 blocks / 4 levels |
| VERSIONINFO key / string value | 64 / 1024 UTF-16 code units (value includes NUL) |
| Manifest preview | 16384 input bytes; an incomplete final character is omitted |
| Total version/manifest input decoded | 262144 bytes |

Malformed data and reached analysis limits produce `Warning: resources:` and
exit status `2`, including explicitly marked truncated manifest previews.
Absent resources are reported as `No resources.` and are not an error.
Resource traversal is enabled only with `-r` / `--resources`.

References: [Microsoft resource directory format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section),
[resource types](https://learn.microsoft.com/en-us/windows/win32/menurc/resource-types),
[VS_VERSIONINFO](https://learn.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo),
[version strings](https://learn.microsoft.com/en-us/windows/win32/menurc/string-str).

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
Build-tool detection excludes overlays and does not fetch PDBs or parse DWARF/CodeView records;
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
* `2`: report produced, but a declared directory count, raw section range, header size, entry point or requested import/export/debug/resource analysis failed validation, or an analysis was incomplete (including resource preview limits).

Raw section ranges are checked against the actual file size. Entry-point offsets are checked against EOF and can resolve into headers. A zero entry-point RVA is displayed as having no entry-point file offset. Non-printable section-name bytes are replaced with `?` in both output modes.

Serialized integer fields are decoded explicitly as little-endian values rather than reading host structures. File positioning uses C `long` (`fseek`/`ftell`); large-file support therefore depends on the host's `long` range. Passing these checks does not guarantee that Windows will load the image.

## Project structure

| Directory | Responsibility |
| --- | --- |
| `src/pe/` | Header and section parsing, RVA/file utilities, import/export tables, Debug Directory/CodeView, resource trees and payload decoding. |
| `src/analysis/` | Entropy calculation and heuristic build-tool detection. |
| `src/cli/` | Arguments, tables, build-tool/debug/resource presentation, terminal formatting and entropy map. |
| `include/pe/` | PE models, constants and parser interfaces. |
| `include/analysis/` | Entropy and build-tool analysis interfaces. |
| `include/cli/` | CLI output interfaces and `version.h`. |
| `test/` | C unit tests, generated PE regression fixtures and optional MinGW test build. |

Parsing callbacks describe imports/exports/debug/resource entries without depending on terminal layout.
`src/pe/debug.c` decodes Debug Directory and CodeView records;
`src/cli/debug_output.c` renders their types, identifiers and sanitized PDB paths.
`src/pe/resources.c` walks resource trees; `resource_version.c` and
`resource_text.c` decode version blocks and Unicode. Their private interfaces
are in `src/pe/resources_internal.h`; `include/pe/resources.h` exposes callbacks.
`src/cli/resources_output.c` renders the tree and escapes untrusted text.
Compiler detection produces `PE_BUILD_INFO`; `src/cli/build_output.c` renders it.
`src/analysis/entropy.c` calculates entropy; `src/cli/graph.c` draws it.
Shared includes use explicit paths such as `pe/image.h` and `analysis/compiler.h`.

The Makefile preserves this hierarchy under `build/` and tracks header
prerequisites through generated `.d` files. After migrating from the flat
layout, run `make clean && make test`. The CLI flags and existing output
remain the same, with the addition of `-e` / `--export`.

## Goals

The project is primarily educational: to understand the PE file format and build a small, focused PE parser from scratch on Linux.

The parser intentionally keeps the default output compact and focused on information that is useful during initial PE inspection.

Additional analysis features are implemented as optional CLI modes rather than making the default output unnecessarily verbose. For example, PE Data Directories and the entropy map are available through dedicated command-line options.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
