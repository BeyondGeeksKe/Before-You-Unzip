# Before You Unzip

> **Look before you unpack.**

**Before You Unzip** is a lightweight, local ZIP inspection utility built by **Beyond Geeks & Voyage**.

It started from a simple engineering question:

> **How much can we learn about an archive before extracting anything?**

The answer turned into a small tool.

Before You Unzip examines ZIP structure, metadata, filenames, compression behaviour and several archive-level warning indicators **without extracting or executing the files inside**.

---

## Why this exists

ZIP files are everywhere.

They arrive through:

- email attachments
- research datasets
- shared drives
- project handovers
- client files
- downloads
- code bundles
- backups
- vendor packages
- internal transfers

The usual workflow is:

```text
Download archive
      ↓
Extract archive
      ↓
See what was inside
```

Before You Unzip adds one step:

```text
Download archive
      ↓
Inspect archive
      ↓
Understand what is inside
      ↓
Review anything unusual
      ↓
Decide what to do next
      ↓
Extract when appropriate
```

The tool does **not** claim this makes an archive safe.

It simply gives you more information before you act.

---

# Current version

```text
Before You Unzip
Version 0.1.0
```

v0.1 focuses exclusively on:

```text
ZIP archives
```

Future versions may support additional archive formats.

---

# What it checks

Before You Unzip currently inspects:

- ZIP readability
- entry count
- file count
- directory count
- file extensions
- nested archives
- encrypted entries
- potentially executable or script-like file types
- suspicious archive paths
- path traversal indicators
- duplicate archive entry names
- ZIP compression methods
- unusually high compression ratios
- ZIP timestamps
- local file-header structure
- central-directory metadata
- selected local-header / central-directory consistency
- CRC metadata consistency
- compressed-size metadata
- uncompressed-size metadata
- UTF-8 filename metadata
- ZIP64 size placeholders

It can generate:

- human-readable terminal output
- JSON reports
- public-safe reports with filenames hidden

---

# What it does NOT do

Before You Unzip is **not antivirus software**.

It does not:

- execute files
- extract files
- launch scripts
- open documents
- analyse executable code
- inspect Office macros
- scan malware signatures
- perform behavioural analysis
- submit data to online scanning services
- determine whether a file is malicious
- guarantee that an archive is safe

A ZIP may pass every current check and still contain dangerous content.

A clean result means:

> **No obvious archive-level issues were detected by the checks currently implemented.**

It does not mean:

> **This archive is safe.**

---

# The rule

Before You Unzip follows a simple idea:

> **Inspect first. Decide second. Extract later.**

---

# Local first

Version 0.1 performs inspection locally.

It does not intentionally:

- upload the ZIP
- upload filenames
- transmit metadata
- call cloud scanning APIs
- send the archive to Beyond Geeks & Voyage
- require an account

The inspection happens on your machine.

---

# Requirements

```text
Python 3.10+
```

Version 0.1 uses Python's standard library only.

No additional dependencies are required.

---

# Repository structure

```text
Before-You-Unzip/
│
├── before_you_unzip.py
├── README.md
├── LICENSE
│
├── docs/
│   └── checks.md
│
└── examples/
    ├── example-report.txt
    └── example-report.json
```

---

# Installation

Clone the repository:

```bash
git clone https://github.com/BeyondGeeksKe/Before-You-Unzip.git
```

Enter the directory:

```bash
cd Before-You-Unzip
```

Check Python:

```bash
python --version
```

or:

```bash
python3 --version
```

---

# Basic usage

```bash
python before_you_unzip.py archive.zip
```

or:

```bash
python3 before_you_unzip.py archive.zip
```

---

# Example

```bash
python before_you_unzip.py delivery.zip
```

Possible output:

```text
Before You Unzip v0.1.0
================================================================

Archive:                  delivery.zip
Archive size:             18.24 MiB
Entries:                  62
Files:                    58
Directories:              4
Declared uncompressed:    48.67 MiB
Compression ratio:        2.67x

Archive-level checks
----------------------------------------------------------------

✓ Encrypted entries                     0
! Nested archives                       1
! Executable/script-like types          1
✓ Suspicious paths                      0
✓ Duplicate names                       0
✓ Metadata findings                     0
✓ High compression-ratio entries        0

File types
----------------------------------------------------------------

.csv             20
.json            12
.png             10
.txt              8
.zip              1
.ps1              1
[none]            6

Findings
----------------------------------------------------------------

i Nested archive detected. [backup.zip]

! Potentially executable or script-like file type detected (.ps1).
  [scripts/setup.ps1]

Important
----------------------------------------------------------------

No files extracted.
No files executed.

This is not an antivirus verdict.
Further scanning may still be appropriate.
```

---

# Understanding the symbols

### `✓`

The check did not identify anything notable.

### `!`

Something deserves attention.

### `i`

Informational context was discovered.

None of these symbols represent a malware verdict.

---

# JSON output

Generate a JSON report:

```bash
python before_you_unzip.py archive.zip --json report.json
```

Example:

```json
{
  "tool": "Before You Unzip",
  "version": "0.1.0",
  "archive": "archive.zip",
  "archive_size_bytes": 19126026,
  "archive_size": "18.24 MiB",
  "summary": {
    "entries": 62,
    "files": 58,
    "directories": 4,
    "encrypted_entries": 0,
    "nested_archives": 1,
    "potentially_executable_file_types": 1,
    "suspicious_paths": 0,
    "duplicate_names": 0,
    "metadata_findings": 0,
    "high_compression_ratio_entries": 0,
    "compressed_size_bytes": 19000000,
    "compressed_size": "18.12 MiB",
    "uncompressed_size_bytes": 51034112,
    "uncompressed_size": "48.67 MiB",
    "overall_compression_ratio": 2.69,
    "warnings": 1,
    "informational_findings": 1
  },
  "file_types": {
    ".csv": 20,
    ".json": 12,
    ".png": 10,
    ".ps1": 1,
    ".txt": 8,
    ".zip": 1,
    "[none]": 6
  },
  "findings": [
    {
      "severity": "info",
      "category": "nested_archive",
      "message": "Nested archive detected.",
      "entry": "backup.zip"
    },
    {
      "severity": "warning",
      "category": "file_type",
      "message": "Potentially executable or script-like file type detected (.ps1).",
      "entry": "scripts/setup.ps1"
    }
  ],
  "notes": [
    "No files were extracted.",
    "No files were executed.",
    "This is archive-level inspection, not an antivirus verdict."
  ]
}
```

---

# Public reports

Sometimes filenames themselves are private.

Use:

```bash
python before_you_unzip.py archive.zip --public-report
```

Instead of:

```text
! Potentially executable or script-like file type detected (.ps1).
  [scripts/setup.ps1]
```

you get:

```text
! Potentially executable or script-like file type detected (.ps1).
```

---

# Public JSON reports

You can combine both features:

```bash
python before_you_unzip.py archive.zip \
  --public-report \
  --json public-report.json
```

Individual entry names are omitted.

This mode is useful for:

- screenshots
- public documentation
- research work
- client archives
- demonstrations
- social media
- incident reports

---

# Large ZIP files

Before You Unzip does **not impose an arbitrary physical ZIP size limit**.

A ZIP being large does not automatically make it suspicious.

Examples:

```text
5 GB ZIP
20 GB ZIP
100 GB ZIP
```

can still be inspected at the metadata level if:

- the filesystem supports the file
- the archive is structurally readable
- the machine has enough resources to maintain the archive entry inventory

The script does **not extract those files**.

---

## ZIP64

Large ZIP archives normally use **ZIP64**.

Python's ZIP library supports ZIP64, and Before You Unzip opens archives with ZIP64 support enabled.

This allows archives exceeding traditional ZIP limits to be inspected.

---

# What matters more than physical size?

One useful indicator is the relationship between:

```text
compressed size
```

and:

```text
declared uncompressed size
```

Example:

```text
100 GB compressed
120 GB uncompressed

ratio ≈ 1.2x
```

That is not inherently unusual.

Compare that with:

```text
20 MB compressed
80 GB uncompressed

ratio ≈ 4096x
```

That deserves attention.

---

# Compression ratio warnings

Version 0.1 defaults to:

```text
100x
```

Example:

```text
! High compression ratio detected (412.35x).
```

This is a heuristic.

High compression does not automatically indicate a malicious archive.

---

# Changing the ratio threshold

```bash
python before_you_unzip.py archive.zip \
  --ratio-warning 200
```

This changes the review threshold to:

```text
200x
```

---

# Entry counts

Archive physical size is not always the biggest resource concern.

For example:

```text
100 GB ZIP
100 files
```

may be easier to inspect than:

```text
2 GB ZIP
5,000,000 tiny files
```

Python keeps ZIP metadata for entries in memory.

For this reason, Before You Unzip has an entry-count review threshold.

Default:

```text
100,000
```

If an archive exceeds it, the tool reports:

```text
Archive contains 250,000 entries,
above the configured review threshold of 100,000.
```

---

# Changing the entry threshold

```bash
python before_you_unzip.py archive.zip \
  --max-entries 500000
```

The current threshold is a **warning threshold**.

It does not automatically stop inspection.

Future versions may add hard resource limits.

---

# File types

Before You Unzip groups archive entries by extension.

Example:

```text
.csv        200
.json        42
.png         12
.exe          1
```

Extensions provide context only.

They do not prove actual file content.

---

# Potential executable/script types

Version 0.1 highlights:

```text
.exe
.dll
.com
.scr
.msi
.bat
.cmd
.ps1
.vbs
.js
.jar
.sh
```

Example:

```text
! Potentially executable or script-like file type detected (.exe).
```

That means:

> This type may execute code.

It does not mean:

> This is malware.

---

# Nested archives

Archive-like files inside the ZIP are reported.

Currently recognised:

```text
.zip
.7z
.rar
.tar
.gz
.tgz
.bz2
.xz
```

Example:

```text
i Nested archive detected. [backup.zip]
```

Nested archives may be completely legitimate.

They are shown because they represent another content layer.

---

# Encryption

Entries with ZIP encryption flags are reported.

Example:

```text
i Encrypted archive entry detected.
```

Encryption itself is not malicious.

It simply limits how much can be inspected without the password.

Before You Unzip does not attempt to:

- break encryption
- guess passwords
- decrypt protected content

---

# Path traversal

Archives can contain paths such as:

```text
../../outside.txt
```

or:

```text
../../../Windows/System32/example.exe
```

Poorly implemented extraction software may write these outside the intended destination.

Before You Unzip flags obvious indicators of:

```text
path traversal
```

sometimes referred to in archive contexts as:

```text
Zip Slip
```

The tool itself performs no extraction.

---

# Duplicate paths

ZIP archives may contain multiple entries using the same path:

```text
settings.json
settings.json
```

Different extractors may behave differently.

Before You Unzip reports duplicates so users know they exist.

---

# ZIP metadata

A simplified ZIP looks roughly like:

```text
[ Local File Header ]
[ Compressed Data ]

[ Local File Header ]
[ Compressed Data ]

[ Local File Header ]
[ Compressed Data ]

          ↓

[ Central Directory ]

          ↓

[ End of Central Directory ]
```

The same entry may be described in more than one location.

Before You Unzip compares selected metadata between those structures.

---

# Header consistency checks

Version 0.1 checks selected fields including:

```text
compression method
encryption flag
CRC
compressed size
uncompressed size
UTF-8 filename information
```

Possible finding:

```text
! Compression method differs between
  local header and central directory.
```

A mismatch may result from:

- corruption
- incomplete writes
- non-standard archive generators
- malformed metadata
- parser edge cases

The tool does not infer intent.

---

# CRC

ZIP files commonly store CRC-32 information.

Version 0.1 compares available CRC metadata where appropriate.

It does **not yet decompress every entry to independently recompute CRC values**.

That is deliberate.

Decompressing unknown archives introduces resource risks.

---

# Data descriptors

Some ZIP entries use:

```text
general-purpose bit flag 3
```

which allows CRC and size fields to appear after the file data.

In these cases, local-header fields may legitimately contain placeholders.

Before You Unzip accounts for this when performing consistency checks.

---

# ZIP64

ZIP64 supports large:

- files
- archives
- entry sizes
- offsets

Classic ZIP fields may contain:

```text
0xFFFFFFFF
```

as ZIP64 placeholders.

Before You Unzip avoids treating known ZIP64 placeholders as normal size mismatches.

---

# Archive readability

Before You Unzip first checks whether the supplied file is recognised as ZIP-compatible.

If not:

```text
Error: file is not recognised as a valid ZIP archive.
```

Possible reasons include:

- corruption
- incomplete download
- wrong extension
- unsupported format
- malformed ZIP structure

---

# Exit codes

```text
0
Inspection completed.

1
Archive processing or report writing failed.

2
Invalid user input or invalid ZIP file.
```

Warnings currently do not change the exit code.

---

# Example workflow

Before You Unzip is intended to sit early in a file-handling workflow:

```text
Receive ZIP
    ↓
Before You Unzip
    ↓
Review findings
    ↓
Run antivirus / security tooling
    ↓
Sandbox where appropriate
    ↓
Extract carefully
```

---

# Project origin

Before You Unzip began as a side quest during work on **Project NEURA**.

While working carefully with research material, we ran into a basic question:

> **Can we understand an archive before immediately unpacking it?**

The answer started as a small internal script.

Then another question came up:

> **Could this be useful to other people too?**

So we decided to build it in the open.

---

# Project NEURA and FinalSpark

The engineering question that inspired this utility arose while working on Project NEURA.

Research data used by Project NEURA is provided courtesy of **FinalSpark**.

No FinalSpark research data is included in this repository.

This repository does not publish:

- FinalSpark datasets
- archive contents
- filenames from research material
- research metadata
- recordings
- derived data
- analysis outputs

Before You Unzip is an independent, general-purpose archive inspection utility.

---

# Why public-report mode exists

Sometimes the archive itself may contain sensitive information in filenames.

For example:

```text
client-name/
patient-id/
research-session/
private-project/
```

A screenshot of an inspection report could unintentionally expose that information.

Public-report mode removes entry names while preserving the finding category.

---

# Roadmap

## v0.1

- [x] ZIP readability
- [x] ZIP64 support
- [x] entry inventory
- [x] file inventory
- [x] directory inventory
- [x] extension summary
- [x] nested archive detection
- [x] encryption indicators
- [x] executable/script-like type indicators
- [x] traversal-path indicators
- [x] duplicate-entry detection
- [x] compression-ratio analysis
- [x] local-header inspection
- [x] central-directory comparison
- [x] CRC metadata comparison
- [x] UTF-8 filename checks
- [x] JSON report
- [x] public-report mode
- [x] configurable entry threshold
- [x] configurable ratio threshold

---

## v0.2 ideas

- [ ] test suite
- [ ] proper package structure
- [ ] configurable severity profiles
- [ ] stronger ZIP64 extra-field validation
- [ ] symbolic-link detection
- [ ] Unicode filename confusion indicators
- [ ] archive comments
- [ ] extra-field parsing
- [ ] optional archive SHA-256 hashing
- [ ] machine-friendly warning exit modes

---

## Later

- [ ] graphical interface
- [ ] drag and drop
- [ ] Windows `.exe`
- [ ] macOS package
- [ ] Linux package
- [ ] HTML report export
- [ ] bounded CRC verification
- [ ] recursive nested-archive inspection
- [ ] additional archive formats
- [ ] accessibility improvements
- [ ] localisation

---

# GUI direction

The command-line tool comes first.

The inspection engine should work before the interface gets fancy.

Later we want the same engine available to people who do not live in terminals.

Conceptually:

```text
┌───────────────────────────────────────┐
│           Before You Unzip            │
│                                       │
│        Drop a ZIP file here           │
│                                       │
│                or                     │
│                                       │
│         [ Choose Archive ]            │
│                                       │
│   No extraction • No execution        │
└───────────────────────────────────────┘
```

The UI should remain separate from the scanning engine.

That allows the engine to eventually support:

- CLI
- desktop app
- automation
- integrations
- CI workflows

---

# Development philosophy

The project should remain:

- lightweight
- understandable
- local-first
- transparent
- cautious
- explicit about limitations

We prefer:

> **3 findings deserve attention.**

over:

> **SAFE**

because archive inspection cannot prove the absence of malicious content.

---

# Contributing

Contributions are welcome.

Useful areas include:

- test coverage
- malformed ZIP edge cases
- metadata validation
- ZIP specification handling
- cross-platform behaviour
- accessibility
- false-positive reduction
- documentation
- UI work

Please do not commit:

- live malware
- private datasets
- client files
- personal information
- proprietary archives
- third-party research data

Synthetic test archives are preferred.

---

# Security

If you discover a vulnerability in Before You Unzip itself, please avoid immediately publishing detailed exploitation steps in a public issue.

A formal security disclosure process will be added as the project matures.

---

# Disclaimer

Before You Unzip provides archive-level inspection information.

It does not guarantee that an archive or its contents are safe.

Use appropriate security controls when handling unfamiliar files.

---

# License

Before You Unzip is released under the **MIT License**.

See:

```text
LICENSE
```

---

# Built by

**Beyond Geeks & Voyage**

Built in Africa.

**People. Products. Ideas for what comes next.**
