# Before You Unzip

**Look before you unpack.**

Before You Unzip is a small ZIP inspection utility from
**Beyond Geeks & Voyage**.

It started from a simple question while working carefully with research
archives:

> How much can we learn about a ZIP file before extracting anything?

The tool inspects archive structure and metadata without extracting or
executing the files inside.

---

## What it checks

Before You Unzip currently looks for:

- unreadable or malformed ZIP archives
- file and folder counts
- file-type distribution
- nested archives
- encrypted entries
- potentially executable or script-like files
- suspicious paths such as `../../`
- duplicate archive paths
- unusually large files
- unusually high compression ratios
- basic timestamp inconsistencies
- mismatches between ZIP local headers and the central directory

---

## What it does NOT do

Before You Unzip is **not an antivirus product**.

A clean report does not mean a file is safe.

The utility only helps you understand an archive before deciding what to
do with it.

It does not:

- execute archive contents
- extract archive contents
- scan files for known malware signatures
- replace antivirus or sandboxing software
- declare an archive safe or unsafe

---

## Requirements

Python 3.10+

No third-party packages are currently required.

---

## Usage

```bash
python before_you_unzip.py example.zip
