#!/usr/bin/env python3
"""
Before You Unzip
Version 0.1.0

A local, read-only ZIP archive inspection utility.

The tool inspects archive structure and metadata without extracting
or executing archive contents.

It is not antivirus software and does not declare archives safe.
"""

from __future__ import annotations

import argparse
import json
import os
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
# Known archive types
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


# ---------------------------------------------------------------------
# File types that deserve attention
#
# Presence does NOT imply malware.
# ---------------------------------------------------------------------

POTENTIALLY_EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".com",
    ".scr",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".sh",
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
    """Convert bytes to a readable representation."""

    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]

    size = float(value)

    for unit in units:

        if size < 1024 or unit == units[-1]:

            if unit == "B":
                return f"{int(size)} B"

            return f"{size:.2f} {unit}"

        size /= 1024

    return f"{value} B"


def extension_for(filename: str) -> str:
    """Return a lowercase file extension."""

    suffix = PurePosixPath(filename).suffix.lower()

    return suffix or "[none]"


def valid_zip_timestamp(
    timestamp: tuple[int, int, int, int, int, int]
) -> bool:

    try:
        datetime(*timestamp)
        return True

    except (ValueError, TypeError):
        return False


def suspicious_path(filename: str) -> bool:
    """
    Detect obvious archive path traversal / absolute-path indicators.

    This does not extract anything.
    """

    normalized = filename.replace("\\", "/")

    path = PurePosixPath(normalized)

    if path.is_absolute():
        return True

    if ".." in path.parts:
        return True

    # Windows drive path:
    # C:/Windows/...
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
    entry: str | None = None,
) -> dict[str, Any]:

    result: dict[str, Any] = {
        "severity": severity,
        "category": category,
        "message": message,
    }

    if entry is not None:
        result["entry"] = entry

    return result


# ---------------------------------------------------------------------
# ZIP local-header inspection
# ---------------------------------------------------------------------

def inspect_local_header(
    raw_file,
    info: zipfile.ZipInfo,
    archive_size: int,
) -> list[str]:

    """
    Compare selected local-header fields against information from
    the central directory.

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

    # Move past the extra field.
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

    # Bit 3 indicates use of a data descriptor.
    #
    # In this situation CRC and sizes in the local
    # header may legitimately contain placeholders.
    uses_data_descriptor = bool(flags & 0x08)

    if not uses_data_descriptor:

        if crc != info.CRC:

            issues.append(
                "CRC differs between "
                "local header and central directory."
            )

        # ZIP64 commonly uses 0xFFFFFFFF placeholders.
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
# Inspection
# ---------------------------------------------------------------------

def inspect_zip(
    archive_path: Path,
    *,
    include_entry_names: bool = True,
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
                    )
                )

            file_count = 0
            directory_count = 0

            encrypted_count = 0
            nested_archive_count = 0
            executable_type_count = 0

            suspicious_path_count = 0
            metadata_finding_count = 0
            high_ratio_count = 0

            total_compressed = 0
            total_uncompressed = 0

            extensions: Counter[str] = Counter()

            seen_names: Counter[str] = Counter()

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

                extensions[extension] += 1


                # -------------------------------------------------
                # Encryption
                # -------------------------------------------------

                if bool(info.flag_bits & 0x1):

                    encrypted_count += 1

                    findings.append(
                        make_finding(
                            "info",
                            "encryption",
                            "Encrypted archive entry detected.",
                            (
                                name
                                if include_entry_names
                                else None
                            ),
                        )
                    )


                # -------------------------------------------------
                # Nested archive
                # -------------------------------------------------

                if extension in ARCHIVE_EXTENSIONS:

                    nested_archive_count += 1

                    findings.append(
                        make_finding(
                            "info",
                            "nested_archive",
                            "Nested archive detected.",
                            (
                                name
                                if include_entry_names
                                else None
                            ),
                        )
                    )


                # -------------------------------------------------
                # Potential executable/script
                # -------------------------------------------------

                if extension in POTENTIALLY_EXECUTABLE_EXTENSIONS:

                    executable_type_count += 1

                    findings.append(
                        make_finding(
                            "warning",
                            "file_type",
                            (
                                "Potentially executable or "
                                "script-like file type detected "
                                f"({extension})."
                            ),
                            (
                                name
                                if include_entry_names
                                else None
                            ),
                        )
                    )


                # -------------------------------------------------
                # Path traversal
                # -------------------------------------------------

                if suspicious_path(name):

                    suspicious_path_count += 1

                    findings.append(
                        make_finding(
                            "warning",
                            "path",
                            (
                                "Suspicious archive path detected "
                                "(possible traversal or absolute path)."
                            ),
                            (
                                name
                                if include_entry_names
                                else None
                            ),
                        )
                    )


                # -------------------------------------------------
                # Timestamp
                # -------------------------------------------------

                if not valid_zip_timestamp(info.date_time):

                    metadata_finding_count += 1

                    findings.append(
                        make_finding(
                            "warning",
                            "metadata",
                            (
                                "Invalid or impossible ZIP "
                                "timestamp detected."
                            ),
                            (
                                name
                                if include_entry_names
                                else None
                            ),
                        )
                    )


                # -------------------------------------------------
                # Compression method
                # -------------------------------------------------

                if info.compress_type not in KNOWN_COMPRESSION_METHODS:

                    findings.append(
                        make_finding(
                            "info",
                            "compression",
                            (
                                "Unknown or unsupported "
                                "compression method: "
                                f"{info.compress_type}"
                            ),
                            (
                                name
                                if include_entry_names
                                else None
                            ),
                        )
                    )


                # -------------------------------------------------
                # Compression ratio
                # -------------------------------------------------

                if info.compress_size > 0:

                    ratio = (
                        info.file_size
                        / info.compress_size
                    )

                    if ratio > ratio_warning:

                        high_ratio_count += 1

                        findings.append(
                            make_finding(
                                "warning",
                                "compression_ratio",
                                (
                                    "High compression ratio detected "
                                    f"({ratio:.2f}x)."
                                ),
                                (
                                    name
                                    if include_entry_names
                                    else None
                                ),
                            )
                        )

                elif info.file_size > 0:

                    high_ratio_count += 1

                    findings.append(
                        make_finding(
                            "warning",
                            "compression_ratio",
                            (
                                "Entry declares non-zero "
                                "uncompressed data while "
                                "compressed size is zero."
                            ),
                            (
                                name
                                if include_entry_names
                                else None
                            ),
                        )
                    )


                # -------------------------------------------------
                # Local header consistency
                # -------------------------------------------------

                header_issues = inspect_local_header(
                    raw_file,
                    info,
                    archive_size,
                )

                for issue in header_issues:

                    metadata_finding_count += 1

                    findings.append(
                        make_finding(
                            "warning",
                            "metadata",
                            issue,
                            (
                                name
                                if include_entry_names
                                else None
                            ),
                        )
                    )


            # -----------------------------------------------------
            # Duplicate names
            # -----------------------------------------------------

            duplicate_names = [

                name

                for name, count
                in seen_names.items()

                if count > 1
            ]

            for name in duplicate_names:

                findings.append(
                    make_finding(
                        "warning",
                        "duplicate",
                        (
                            "Duplicate archive entry name "
                            f"detected ({seen_names[name]} occurrences)."
                        ),
                        (
                            name
                            if include_entry_names
                            else None
                        ),
                    )
                )


            # -----------------------------------------------------
            # Overall expansion ratio
            # -----------------------------------------------------

            overall_ratio = None

            if total_compressed > 0:

                overall_ratio = (
                    total_uncompressed
                    / total_compressed
                )

                if overall_ratio > ratio_warning:

                    findings.append(
                        make_finding(
                            "warning",
                            "compression_ratio",
                            (
                                "Archive-wide compression ratio "
                                f"is high ({overall_ratio:.2f}x)."
                            ),
                        )
                    )


            # -----------------------------------------------------
            # Summary
            # -----------------------------------------------------

            report["file_types"] = dict(
                sorted(
                    extensions.items()
                )
            )

            report["summary"] = {

                "entries": total_entries,

                "files": file_count,

                "directories": directory_count,

                "encrypted_entries": encrypted_count,

                "nested_archives": nested_archive_count,

                "potentially_executable_file_types":
                    executable_type_count,

                "suspicious_paths":
                    suspicious_path_count,

                "duplicate_names":
                    len(duplicate_names),

                "metadata_findings":
                    metadata_finding_count,

                "high_compression_ratio_entries":
                    high_ratio_count,

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
# CLI output
# ---------------------------------------------------------------------

def print_report(
    report: dict[str, Any],
) -> None:

    summary = report["summary"]

    findings = report["findings"]

    print()

    print(
        f"{APP_NAME} v{report['version']}"
    )

    print("=" * 64)

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

    ratio = summary[
        "overall_compression_ratio"
    ]

    if ratio is None:

        print(
            "Compression ratio:        n/a"
        )

    else:

        print(
            f"Compression ratio:        "
            f"{ratio:.2f}x"
        )


    print()

    print(
        "Archive-level checks"
    )

    print("-" * 64)


    checks = [

        (
            "Encrypted entries",
            summary[
                "encrypted_entries"
            ],
        ),

        (
            "Nested archives",
            summary[
                "nested_archives"
            ],
        ),

        (
            "Executable/script-like types",
            summary[
                "potentially_executable_file_types"
            ],
        ),

        (
            "Suspicious paths",
            summary[
                "suspicious_paths"
            ],
        ),

        (
            "Duplicate names",
            summary[
                "duplicate_names"
            ],
        ),

        (
            "Metadata findings",
            summary[
                "metadata_findings"
            ],
        ),

        (
            "High compression-ratio entries",
            summary[
                "high_compression_ratio_entries"
            ],
        ),
    ]


    for label, value in checks:

        marker = (
            "!"
            if value
            else "✓"
        )

        print(
            f"{marker} "
            f"{label:<38} "
            f"{value}"
        )


    print()

    print(
        "File types"
    )

    print("-" * 64)


    if report["file_types"]:

        for extension, count in report[
            "file_types"
        ].items():

            print(
                f"{extension:<16} "
                f"{count}"
            )

    else:

        print(
            "No file entries found."
        )


    print()

    print(
        "Findings"
    )

    print("-" * 64)


    if not findings:

        print(
            "No obvious archive-level "
            "warnings were found."
        )

    else:

        for item in findings:

            marker = (
                "!"
                if item["severity"]
                == "warning"
                else "i"
            )

            entry = ""

            if "entry" in item:

                entry = (
                    f" [{item['entry']}]"
                )

            print(
                f"{marker} "
                f"{item['message']}"
                f"{entry}"
            )


    print()

    print(
        "Important"
    )

    print("-" * 64)

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
        "Further scanning may still "
        "be appropriate."
    )

    print()


# ---------------------------------------------------------------------
# Argument parser
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

        help=(
            "Path to the ZIP archive."
        ),
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
            "Hide individual archive "
            "entry names from findings."
        ),
    )


    parser.add_argument(

        "--max-entries",

        type=int,

        default=DEFAULT_MAX_ENTRIES,

        help=(
            "Entry-count review threshold. "
            f"Default: "
            f"{DEFAULT_MAX_ENTRIES:,}"
        ),
    )


    parser.add_argument(

        "--ratio-warning",

        type=float,

        default=
            DEFAULT_COMPRESSION_RATIO_WARNING,

        help=(
            "Compression ratio warning "
            "threshold. "
            f"Default: "
            f"{DEFAULT_COMPRESSION_RATIO_WARNING:g}x"
        ),
    )


    parser.add_argument(

        "--version",

        action="version",

        version=(
            f"%(prog)s {VERSION}"
        ),
    )


    return parser.parse_args()


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main() -> int:

    args = parse_arguments()

    if args.max_entries < 1:

        print(
            "Error: --max-entries "
            "must be greater than zero.",
            file=sys.stderr,
        )

        return 2


    if args.ratio_warning <= 0:

        print(
            "Error: --ratio-warning "
            "must be greater than zero.",
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

            include_entry_names=(
                not args.public_report
            ),

            max_entries=
                args.max_entries,

            ratio_warning=
                args.ratio_warning,
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
        report
    )


    if args.json_path:

        output_path = (
            args.json_path
            .expanduser()
            .resolve()
        )

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )


        try:

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
