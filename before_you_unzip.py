#!/usr/bin/env python3
"""
Before You Unzip
Version 0.1.0

A local, read-only ZIP archive inspection utility.

Inspect first. Decide second. Extract later.

Before You Unzip examines ZIP structure and metadata without
extracting or executing archive contents.

This is not antivirus software and does not declare archives safe.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
import zipfile

from collections import Counter
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any


# ---------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------

APP_NAME = "Before You Unzip"
VERSION = "0.1.0"

LOCAL_FILE_HEADER_SIGNATURE = 0x04034B50


# ---------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------

DEFAULT_MAX_ENTRIES = 100_000
DEFAULT_COMPRESSION_RATIO_WARNING = 100.0


# ---------------------------------------------------------------------
# File classifications
# ---------------------------------------------------------------------

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".7z",
    ".rar",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
}


# Code / scripting files.
#
# Their presence is informational context.
# They are not treated the same as native binary executables.
SCRIPT_CODE_EXTENSIONS = {
    ".js",
    ".mjs",
    ".cjs",
    ".ps1",
    ".sh",
    ".bat",
    ".cmd",
    ".vbs",
    ".py",
    ".rb",
    ".pl",
    ".php",
}


# File types capable of representing native/program executable content.
#
# Presence still does NOT imply maliciousness.
BINARY_EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".com",
    ".scr",
    ".msi",
    ".jar",
}


KNOWN_COMPRESSION_METHODS = {
    zipfile.ZIP_STORED,
    zipfile.ZIP_DEFLATED,
    zipfile.ZIP_BZIP2,
    zipfile.ZIP_LZMA,
}


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def human_bytes(value: int) -> str:
    """Convert bytes into a human-readable string."""

    units = [
        "B",
        "KiB",
        "MiB",
        "GiB",
        "TiB",
        "PiB",
    ]

    size = float(value)

    for unit in units:

        if size < 1024 or unit == units[-1]:

            if unit == "B":
                return f"{int(size)} B"

            return f"{size:.2f} {unit}"

        size /= 1024

    return f"{value} B"


def extension_for(filename: str) -> str:
    """Return lowercase suffix or [none]."""

    suffix = PurePosixPath(filename).suffix.lower()

    return suffix or "[none]"


def valid_zip_timestamp(
    timestamp: tuple[int, int, int, int, int, int]
) -> bool:
    """Check whether a ZIP timestamp represents a valid date/time."""

    try:
        datetime(*timestamp)
        return True

    except (ValueError, TypeError):
        return False


def suspicious_path(filename: str) -> bool:
    """
    Detect obvious traversal or absolute-path indicators.

    No extraction occurs.
    """

    normalized = filename.replace("\\", "/")

    path = PurePosixPath(normalized)

    # Unix-style absolute path.
    if path.is_absolute():
        return True

    # Parent traversal.
    if ".." in path.parts:
        return True

    # Windows drive path: C:/...
    if (
        len(normalized) >= 3
        and normalized[1] == ":"
        and normalized[2] == "/"
    ):
        return True

    return False


def make_finding(
    severity: str,
    category: str,
    message: str,
    count: int | None = None,
    entries: list[str] | None = None,
) -> dict[str, Any]:

    result: dict[str, Any] = {
        "severity": severity,
        "category": category,
        "message": message,
    }

    if count is not None:
        result["count"] = count

    if entries:
        result["entries"] = entries

    return result


# ---------------------------------------------------------------------
# Local ZIP header inspection
# ---------------------------------------------------------------------

def inspect_local_header(
    raw_file,
    info: zipfile.ZipInfo,
    archive_size: int,
) -> list[str]:
    """
    Compare selected local-header fields against the central directory.

    No decompression is performed.
    """

    issues: list[str] = []

    offset = info.header_offset

    if offset < 0 or offset >= archive_size:
        return [
            "Local header offset points outside the archive."
        ]

    raw_file.seek(offset)

    header = raw_file.read(30)

    if len(header) != 30:
        return [
            "Local file header is truncated."
        ]

    try:

        (
            signature,
            _version_needed,
            flags,
            compression_method,
            _modified_time,
            _modified_date,
            crc,
            compressed_size,
            uncompressed_size,
            filename_length,
            extra_length,
        ) = struct.unpack(
            "<IHHHHHIIIHH",
            header,
        )

    except struct.error:

        return [
            "Local file header could not be parsed."
        ]

    if signature != LOCAL_FILE_HEADER_SIGNATURE:
        return [
            "Invalid local file header signature."
        ]

    if compression_method != info.compress_type:

        issues.append(
            "Compression method differs between "
            "local header and central directory."
        )

    local_encrypted = bool(flags & 0x1)
    central_encrypted = bool(info.flag_bits & 0x1)

    if local_encrypted != central_encrypted:

        issues.append(
            "Encryption flag differs between "
            "local header and central directory."
        )

    filename_bytes = raw_file.read(filename_length)

    # Skip the extra field.
    raw_file.read(extra_length)

    # UTF-8 filename flag.
    if flags & 0x800:

        try:

            local_filename = filename_bytes.decode("utf-8")

            if local_filename != info.filename:

                issues.append(
                    "Filename differs between "
                    "local header and central directory."
                )

        except UnicodeDecodeError:

            issues.append(
                "UTF-8 filename flag is set but "
                "the filename is not valid UTF-8."
            )

    # Bit 3 indicates a data descriptor may contain CRC/sizes later.
    uses_data_descriptor = bool(flags & 0x08)

    if not uses_data_descriptor:

        if crc != info.CRC:

            issues.append(
                "CRC differs between "
                "local header and central directory."
            )

        # ZIP64 may use 0xFFFFFFFF placeholders.
        if (
            compressed_size != 0xFFFFFFFF
            and compressed_size != info.compress_size
        ):

            issues.append(
                "Compressed size differs between "
                "local header and central directory."
            )

        if (
            uncompressed_size != 0xFFFFFFFF
            and uncompressed_size != info.file_size
        ):

            issues.append(
                "Uncompressed size differs between "
                "local header and central directory."
            )

    return issues


# ---------------------------------------------------------------------
# Archive inspection
# ---------------------------------------------------------------------

def inspect_zip(
    archive_path: Path,
    *,
    public_report: bool = False,
    verbose: bool = False,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    ratio_warning: float = DEFAULT_COMPRESSION_RATIO_WARNING,
) -> dict[str, Any]:

    archive_size = archive_path.stat().st_size

    report: dict[str, Any] = {
        "tool": APP_NAME,
        "version": VERSION,
        "archive": archive_path.name,
        "archive_size_bytes": archive_size,
        "archive_size": human_bytes(archive_size),
        "summary": {},
        "file_types": {},
        "script_code_types": {},
        "binary_executable_types": {},
        "findings": [],
        "notes": [
            "No files were extracted.",
            "No files were executed.",
            "This is archive-level inspection, not an antivirus verdict.",
        ],
    }

    findings: list[dict[str, Any]] = report["findings"]

    with open(archive_path, "rb") as raw_file:

        with zipfile.ZipFile(
            archive_path,
            mode="r",
            allowZip64=True,
        ) as archive:

            infos = archive.infolist()

            total_entries = len(infos)

            file_count = 0
            directory_count = 0

            total_compressed = 0
            total_uncompressed = 0

            extension_counts: Counter[str] = Counter()

            script_counts: Counter[str] = Counter()
            binary_counts: Counter[str] = Counter()

            encrypted_entries: list[str] = []
            nested_entries: list[str] = []
            suspicious_entries: list[str] = []
            high_ratio_entries: list[str] = []
            metadata_entries: list[str] = []

            metadata_messages: Counter[str] = Counter()

            duplicate_names: list[str] = []

            seen_names: Counter[str] = Counter()

            unknown_compression_entries: list[str] = []

            # -----------------------------------------------------
            # Entry count
            # -----------------------------------------------------

            if total_entries > max_entries:

                findings.append(
                    make_finding(
                        "warning",
                        "entry_count",
                        (
                            f"Archive contains {total_entries:,} entries, "
                            f"above the configured review threshold "
                            f"of {max_entries:,}."
                        ),
                        count=total_entries,
                    )
                )

            # -----------------------------------------------------
            # Per-entry inspection
            # -----------------------------------------------------

            for info in infos:

                name = info.filename

                seen_names[name] += 1

                if info.is_dir():

                    directory_count += 1
                    continue

                file_count += 1

                total_compressed += info.compress_size
                total_uncompressed += info.file_size

                extension = extension_for(name)

                extension_counts[extension] += 1

                # -------------------------------------------------
                # Script / code classification
                # -------------------------------------------------

                if extension in SCRIPT_CODE_EXTENSIONS:
                    script_counts[extension] += 1

                # -------------------------------------------------
                # Binary executable classification
                # -------------------------------------------------

                if extension in BINARY_EXECUTABLE_EXTENSIONS:
                    binary_counts[extension] += 1

                # -------------------------------------------------
                # Encryption
                # -------------------------------------------------

                if bool(info.flag_bits & 0x1):
                    encrypted_entries.append(name)

                # -------------------------------------------------
                # Nested archives
                # -------------------------------------------------

                if extension in ARCHIVE_EXTENSIONS:
                    nested_entries.append(name)

                # -------------------------------------------------
                # Suspicious paths
                # -------------------------------------------------

                if suspicious_path(name):
                    suspicious_entries.append(name)

                # -------------------------------------------------
                # Timestamp
                # -------------------------------------------------

                if not valid_zip_timestamp(info.date_time):

                    metadata_entries.append(name)

                    metadata_messages[
                        "Invalid or impossible ZIP timestamp detected."
                    ] += 1

                # -------------------------------------------------
                # Compression method
                # -------------------------------------------------

                if info.compress_type not in KNOWN_COMPRESSION_METHODS:
                    unknown_compression_entries.append(name)

                # -------------------------------------------------
                # Compression ratio
                # -------------------------------------------------

                if info.compress_size > 0:

                    ratio = (
                        info.file_size
                        / info.compress_size
                    )

                    if ratio > ratio_warning:
                        high_ratio_entries.append(name)

                elif info.file_size > 0:

                    high_ratio_entries.append(name)

                # -------------------------------------------------
                # Header consistency
                # -------------------------------------------------

                header_issues = inspect_local_header(
                    raw_file,
                    info,
                    archive_size,
                )

                for issue in header_issues:

                    metadata_entries.append(name)
                    metadata_messages[issue] += 1

            # -----------------------------------------------------
            # Duplicate names
            # -----------------------------------------------------

            duplicate_names = [
                name
                for name, count in seen_names.items()
                if count > 1
            ]

            # -----------------------------------------------------
            # Overall ratio
            # -----------------------------------------------------

            overall_ratio = None

            if total_compressed > 0:

                overall_ratio = (
                    total_uncompressed
                    / total_compressed
                )

            # -----------------------------------------------------
            # Aggregated findings
            # -----------------------------------------------------

            if script_counts:

                total_scripts = sum(script_counts.values())

                entries = None

                if verbose and not public_report:

                    entries = [
                        info.filename
                        for info in infos
                        if (
                            not info.is_dir()
                            and extension_for(info.filename)
                            in SCRIPT_CODE_EXTENSIONS
                        )
                    ]

                findings.append(
                    make_finding(
                        "info",
                        "script_code",
                        (
                            f"{total_scripts:,} script/code "
                            f"file entries detected."
                        ),
                        count=total_scripts,
                        entries=entries,
                    )
                )

            if binary_counts:

                total_binaries = sum(binary_counts.values())

                entries = None

                if verbose and not public_report:

                    entries = [
                        info.filename
                        for info in infos
                        if (
                            not info.is_dir()
                            and extension_for(info.filename)
                            in BINARY_EXECUTABLE_EXTENSIONS
                        )
                    ]

                findings.append(
                    make_finding(
                        "warning",
                        "binary_executable",
                        (
                            f"{total_binaries:,} executable/binary "
                            f"file entries detected."
                        ),
                        count=total_binaries,
                        entries=entries,
                    )
                )

            if encrypted_entries:

                findings.append(
                    make_finding(
                        "info",
                        "encryption",
                        (
                            f"{len(encrypted_entries):,} encrypted "
                            f"archive entries detected."
                        ),
                        count=len(encrypted_entries),
                        entries=(
                            encrypted_entries
                            if verbose and not public_report
                            else None
                        ),
                    )
                )

            if nested_entries:

                findings.append(
                    make_finding(
                        "info",
                        "nested_archive",
                        (
                            f"{len(nested_entries):,} nested "
                            f"archive entries detected."
                        ),
                        count=len(nested_entries),
                        entries=(
                            nested_entries
                            if verbose and not public_report
                            else None
                        ),
                    )
                )

            if suspicious_entries:

                findings.append(
                    make_finding(
                        "warning",
                        "path",
                        (
                            f"{len(suspicious_entries):,} suspicious "
                            f"archive paths detected."
                        ),
                        count=len(suspicious_entries),
                        entries=(
                            suspicious_entries
                            if verbose and not public_report
                            else None
                        ),
                    )
                )

            if duplicate_names:

                findings.append(
                    make_finding(
                        "warning",
                        "duplicate",
                        (
                            f"{len(duplicate_names):,} duplicate "
                            f"archive entry names detected."
                        ),
                        count=len(duplicate_names),
                        entries=(
                            duplicate_names
                            if verbose and not public_report
                            else None
                        ),
                    )
                )

            if metadata_entries:

                unique_metadata_entries = list(
                    dict.fromkeys(metadata_entries)
                )

                findings.append(
                    make_finding(
                        "warning",
                        "metadata",
                        (
                            f"{len(unique_metadata_entries):,} entries "
                            f"have metadata/header findings."
                        ),
                        count=len(unique_metadata_entries),
                        entries=(
                            unique_metadata_entries
                            if verbose and not public_report
                            else None
                        ),
                    )
                )

            if unknown_compression_entries:

                findings.append(
                    make_finding(
                        "info",
                        "compression_method",
                        (
                            f"{len(unknown_compression_entries):,} entries "
                            f"use unknown or unsupported "
                            f"compression methods."
                        ),
                        count=len(unknown_compression_entries),
                        entries=(
                            unknown_compression_entries
                            if verbose and not public_report
                            else None
                        ),
                    )
                )

            if high_ratio_entries:

                findings.append(
                    make_finding(
                        "warning",
                        "compression_ratio",
                        (
                            f"{len(high_ratio_entries):,} entries exceed "
                            f"the configured compression-ratio review "
                            f"threshold of {ratio_warning:g}x."
                        ),
                        count=len(high_ratio_entries),
                        entries=(
                            high_ratio_entries
                            if verbose and not public_report
                            else None
                        ),
                    )
                )

            if (
                overall_ratio is not None
                and overall_ratio > ratio_warning
            ):

                findings.append(
                    make_finding(
                        "warning",
                        "archive_compression_ratio",
                        (
                            "Archive-wide compression ratio "
                            f"is high ({overall_ratio:.2f}x)."
                        ),
                    )
                )

            # -----------------------------------------------------
            # Report data
            # -----------------------------------------------------

            report["file_types"] = dict(
                sorted(extension_counts.items())
            )

            report["script_code_types"] = dict(
                sorted(script_counts.items())
            )

            report["binary_executable_types"] = dict(
                sorted(binary_counts.items())
            )

            report["metadata_issue_types"] = dict(
                metadata_messages
            )

            report["summary"] = {
                "entries": total_entries,
                "files": file_count,
                "directories": directory_count,

                "script_code_entries":
                    sum(script_counts.values()),

                "binary_executable_entries":
                    sum(binary_counts.values()),

                "encrypted_entries":
                    len(encrypted_entries),

                "nested_archives":
                    len(nested_entries),

                "suspicious_paths":
                    len(suspicious_entries),

                "duplicate_names":
                    len(duplicate_names),

                "metadata_findings":
                    len(
                        list(
                            dict.fromkeys(
                                metadata_entries
                            )
                        )
                    ),

                "unknown_compression_methods":
                    len(unknown_compression_entries),

                "high_compression_ratio_entries":
                    len(high_ratio_entries),

                "compressed_size_bytes":
                    total_compressed,

                "compressed_size":
                    human_bytes(total_compressed),

                "uncompressed_size_bytes":
                    total_uncompressed,

                "uncompressed_size":
                    human_bytes(total_uncompressed),

                "overall_compression_ratio":
                    (
                        round(overall_ratio, 2)
                        if overall_ratio is not None
                        else None
                    ),

                "warnings":
                    sum(
                        1
                        for item in findings
                        if item["severity"] == "warning"
                    ),

                "informational_findings":
                    sum(
                        1
                        for item in findings
                        if item["severity"] == "info"
                    ),
            }

    return report


# ---------------------------------------------------------------------
# CLI report
# ---------------------------------------------------------------------

def print_report(
    report: dict[str, Any],
    *,
    verbose: bool = False,
) -> None:

    summary = report["summary"]
    findings = report["findings"]

    print()
    print(
        f"{APP_NAME} v{report['version']}"
    )
    print("=" * 68)

    print(
        f"Archive:                  "
        f"{report['archive']}"
    )

    print(
        f"Archive size:             "
        f"{report['archive_size']}"
    )

    print(
        f"Entries:                  "
        f"{summary['entries']:,}"
    )

    print(
        f"Files:                    "
        f"{summary['files']:,}"
    )

    print(
        f"Directories:              "
        f"{summary['directories']:,}"
    )

    print(
        f"Declared uncompressed:    "
        f"{summary['uncompressed_size']}"
    )

    ratio = summary["overall_compression_ratio"]

    if ratio is None:

        print(
            "Compression ratio:        n/a"
        )

    else:

        print(
            f"Compression ratio:        "
            f"{ratio:.2f}x"
        )

    # -----------------------------------------------------------------
    # Main checks
    # -----------------------------------------------------------------

    print()
    print("Archive-level checks")
    print("-" * 68)

    checks = [
        (
            "Encrypted entries",
            summary["encrypted_entries"],
            "info",
        ),
        (
            "Nested archives",
            summary["nested_archives"],
            "info",
        ),
        (
            "Script/code entries",
            summary["script_code_entries"],
            "info",
        ),
        (
            "Executable/binary entries",
            summary["binary_executable_entries"],
            "warning",
        ),
        (
            "Suspicious paths",
            summary["suspicious_paths"],
            "warning",
        ),
        (
            "Duplicate names",
            summary["duplicate_names"],
            "warning",
        ),
        (
            "Metadata findings",
            summary["metadata_findings"],
            "warning",
        ),
        (
            "High compression-ratio entries",
            summary["high_compression_ratio_entries"],
            "warning",
        ),
    ]

    for label, value, finding_type in checks:

        if value == 0:
            marker = "✓"

        elif finding_type == "info":
            marker = "i"

        else:
            marker = "!"

        print(
            f"{marker} "
            f"{label:<40} "
            f"{value:,}"
        )

    # -----------------------------------------------------------------
    # Code/script summary
    # -----------------------------------------------------------------

    if report["script_code_types"]:

        print()
        print("Script / code types")
        print("-" * 68)

        for extension, count in report[
            "script_code_types"
        ].items():

            print(
                f"{extension:<16} "
                f"{count:,}"
            )

        print()
        print(
            "Note: script/code files can contain executable logic, "
            "but their presence alone does not indicate malicious content."
        )

    # -----------------------------------------------------------------
    # Binary executable summary
    # -----------------------------------------------------------------

    if report["binary_executable_types"]:

        print()
        print("Executable / binary types")
        print("-" * 68)

        for extension, count in report[
            "binary_executable_types"
        ].items():

            print(
                f"{extension:<16} "
                f"{count:,}"
            )

        print()
        print(
            "Executable or binary file types deserve review, "
            "but their presence alone is not a malware verdict."
        )

    # -----------------------------------------------------------------
    # General file types
    # -----------------------------------------------------------------

    print()
    print("File types")
    print("-" * 68)

    if report["file_types"]:

        for extension, count in report[
            "file_types"
        ].items():

            print(
                f"{extension:<16} "
                f"{count:,}"
            )

    else:

        print(
            "No file entries found."
        )

    # -----------------------------------------------------------------
    # Findings
    # -----------------------------------------------------------------

    print()
    print("Findings")
    print("-" * 68)

    if not findings:

        print(
            "No obvious archive-level warnings were found."
        )

    else:

        for item in findings:

            marker = (
                "!"
                if item["severity"] == "warning"
                else "i"
            )

            print(
                f"{marker} {item['message']}"
            )

            if verbose and item.get("entries"):

                for entry in item["entries"]:
                    print(
                        f"    - {entry}"
                    )

    # -----------------------------------------------------------------
    # Summary interpretation
    # -----------------------------------------------------------------

    print()
    print("Archive posture")
    print("-" * 68)

    if summary["metadata_findings"] == 0:
        print(
            "Structural metadata:      No obvious issues"
        )
    else:
        print(
            "Structural metadata:      Review findings"
        )

    if summary["suspicious_paths"] == 0:
        print(
            "Path handling:            No obvious issues"
        )
    else:
        print(
            "Path handling:            Review findings"
        )

    if summary["high_compression_ratio_entries"] == 0:
        print(
            "Expansion behaviour:      No obvious ratio warnings"
        )
    else:
        print(
            "Expansion behaviour:      Review findings"
        )

    if summary["binary_executable_entries"] == 0:
        print(
            "Binary executables:       None detected by extension"
        )
    else:
        print(
            f"Binary executables:       "
            f"{summary['binary_executable_entries']:,} detected"
        )

    if summary["script_code_entries"] == 0:
        print(
            "Script/code entries:      None detected"
        )
    else:
        print(
            f"Script/code entries:      "
            f"{summary['script_code_entries']:,} detected"
        )

    # -----------------------------------------------------------------
    # Important footer
    # -----------------------------------------------------------------

    print()
    print("Important")
    print("-" * 68)

    print(
        "No files extracted."
    )

    print(
        "No files executed."
    )

    print()

    print(
        "This is not an antivirus verdict."
    )

    print(
        "Further scanning may still be appropriate."
    )

    print()


# ---------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        prog="before-you-unzip",
        description=(
            "Inspect ZIP structure and metadata "
            "before unpacking the archive."
        ),
    )

    parser.add_argument(
        "archive",
        type=Path,
        help="Path to the ZIP archive.",
    )

    parser.add_argument(
        "--json",
        dest="json_path",
        type=Path,
        help=(
            "Write inspection results "
            "to a JSON report."
        ),
    )

    parser.add_argument(
        "--public-report",
        action="store_true",
        help=(
            "Hide individual archive-entry names "
            "from detailed output."
        ),
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help=(
            "Show individual archive-entry names "
            "for findings."
        ),
    )

    parser.add_argument(
        "--max-entries",
        type=int,
        default=DEFAULT_MAX_ENTRIES,
        help=(
            "Entry-count review threshold. "
            f"Default: {DEFAULT_MAX_ENTRIES:,}"
        ),
    )

    parser.add_argument(
        "--ratio-warning",
        type=float,
        default=DEFAULT_COMPRESSION_RATIO_WARNING,
        help=(
            "Compression ratio review threshold. "
            f"Default: "
            f"{DEFAULT_COMPRESSION_RATIO_WARNING:g}x"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    return parser.parse_args()


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main() -> int:

    args = parse_arguments()

    if args.max_entries < 1:

        print(
            "Error: --max-entries must be greater than zero.",
            file=sys.stderr,
        )

        return 2

    if args.ratio_warning <= 0:

        print(
            "Error: --ratio-warning must be greater than zero.",
            file=sys.stderr,
        )

        return 2

    archive_path = (
        args.archive
        .expanduser()
        .resolve()
    )

    if not archive_path.exists():

        print(
            f"Error: file does not exist: "
            f"{archive_path}",
            file=sys.stderr,
        )

        return 2

    if not archive_path.is_file():

        print(
            f"Error: path is not a file: "
            f"{archive_path}",
            file=sys.stderr,
        )

        return 2

    if not zipfile.is_zipfile(
        archive_path
    ):

        print(
            "Error: file is not recognised "
            "as a valid ZIP archive.",
            file=sys.stderr,
        )

        return 2

    try:

        report = inspect_zip(
            archive_path,
            public_report=args.public_report,
            verbose=args.verbose,
            max_entries=args.max_entries,
            ratio_warning=args.ratio_warning,
        )

    except (
        OSError,
        zipfile.BadZipFile,
        RuntimeError,
        NotImplementedError,
    ) as exc:

        print(
            f"Error while inspecting archive: "
            f"{exc}",
            file=sys.stderr,
        )

        return 1

    print_report(
        report,
        verbose=(
            args.verbose
            and not args.public_report
        ),
    )

    if args.json_path:

        output_path = (
            args.json_path
            .expanduser()
            .resolve()
        )

        try:

            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with open(
                output_path,
                "w",
                encoding="utf-8",
            ) as handle:

                json.dump(
                    report,
                    handle,
                    indent=2,
                    ensure_ascii=False,
                )

                handle.write("\n")

        except OSError as exc:

            print(
                f"Error writing JSON report: "
                f"{exc}",
                file=sys.stderr,
            )

            return 1

        print(
            f"JSON report written to: "
            f"{output_path}"
        )

    return 0


if __name__ == "__main__":

    raise SystemExit(
        main()
    )
