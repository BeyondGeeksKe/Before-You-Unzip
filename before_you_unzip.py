#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import struct
import sys
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path, PurePosixPath


VERSION = "0.1.0"

LOCAL_FILE_HEADER_SIGNATURE = 0x04034B50

ARCHIVE_EXTENSIONS = {
    ".zip", ".7z", ".rar", ".tar", ".gz",
    ".tgz", ".bz2", ".xz"
}

POTENTIALLY_RISKY_EXTENSIONS = {
    ".exe", ".dll", ".com", ".scr", ".msi",
    ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".jar", ".sh"
}

KNOWN_COMPRESSION_METHODS = {
    zipfile.ZIP_STORED,
    zipfile.ZIP_DEFLATED,
    zipfile.ZIP_BZIP2,
    zipfile.ZIP_LZMA,
}

MAX_ENTRY_COUNT = 100_000
MAX_TOTAL_UNCOMPRESSED = 2 * 1024 * 1024 * 1024
MAX_SINGLE_UNCOMPRESSED = 500 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100.0


def human_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(value)

    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"

        size /= 1024

    return f"{value} B"


def extension_for(name: str) -> str:
    suffix = PurePosixPath(name).suffix.lower()
    return suffix or "[none]"


def is_suspicious_path(name: str) -> bool:
    normalised = name.replace("\\", "/")
    path = PurePosixPath(normalised)

    if path.is_absolute():
        return True

    if ".." in path.parts:
        return True

    if (
        len(normalised) >= 3
        and normalised[1] == ":"
        and normalised[2] == "/"
    ):
        return True

    return False


def timestamp_is_valid(info: zipfile.ZipInfo) -> bool:
    try:
        datetime(*info.date_time)
        return True
    except (ValueError, TypeError):
        return False


def inspect_local_header(
    raw_file,
    info: zipfile.ZipInfo,
    archive_size: int,
) -> list[str]:

    issues = []

    offset = info.header_offset

    if offset < 0 or offset >= archive_size:
        return ["Local header offset points outside the archive"]

    raw_file.seek(offset)
    header = raw_file.read(30)

    if len(header) != 30:
        return ["Local file header is truncated"]

    try:
        (
            signature,
            _version_needed,
            flags,
            compression,
            _mod_time,
            _mod_date,
            crc,
            compressed_size,
            uncompressed_size,
            filename_length,
            extra_length,
        ) = struct.unpack("<IHHHHHIIIHH", header)

    except struct.error:
        return ["Local file header could not be parsed"]

    if signature != LOCAL_FILE_HEADER_SIGNATURE:
        issues.append("Invalid local file header signature")
        return issues

    if compression != info.compress_type:
        issues.append(
            "Compression method differs between headers"
        )

    local_encrypted = bool(flags & 0x1)
    central_encrypted = bool(info.flag_bits & 0x1)

    if local_encrypted != central_encrypted:
        issues.append(
            "Encryption flag differs between headers"
        )

    filename_bytes = raw_file.read(filename_length)
    raw_file.read(extra_length)

    if flags & 0x800:
        try:
            local_name = filename_bytes.decode("utf-8")

            if local_name != info.filename:
                issues.append(
                    "Filename differs between headers"
                )

        except UnicodeDecodeError:
            issues.append(
                "UTF-8 filename flag is set but filename "
                "is not valid UTF-8"
            )

    uses_data_descriptor = bool(flags & 0x08)

    if not uses_data_descriptor:

        if crc != info.CRC:
            issues.append(
                "CRC differs between headers"
            )

        if (
            compressed_size != 0xFFFFFFFF
            and compressed_size != info.compress_size
        ):
            issues.append(
                "Compressed size differs between headers"
            )

        if (
            uncompressed_size != 0xFFFFFFFF
            and uncompressed_size != info.file_size
        ):
            issues.append(
                "Uncompressed size differs between headers"
            )

    return issues


def finding(
    severity: str,
    category: str,
    message: str,
    entry: str | None = None,
) -> dict:

    result = {
        "severity": severity,
        "category": category,
        "message": message,
    }

    if entry is not None:
        result["entry"] = entry

    return result


def inspect_zip(
    archive_path: Path,
    include_entry_names: bool = True,
) -> dict:

    archive_size = archive_path.stat().st_size

    report = {
        "tool": "Before You Unzip",
        "version": VERSION,
        "archive": archive_path.name,
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

    findings = report["findings"]

    with open(archive_path, "rb") as raw_file:

        with zipfile.ZipFile(archive_path, "r") as archive:

            infos = archive.infolist()

            if len(infos) > MAX_ENTRY_COUNT:
                findings.append(
                    finding(
                        "warning",
                        "limits",
                        (
                            f"Archive contains {len(infos):,} entries, "
                            f"above the configured limit."
                        ),
                    )
                )

            file_count = 0
            directory_count = 0
            encrypted_count = 0
            nested_archive_count = 0
            risky_file_count = 0
            suspicious_path_count = 0
            metadata_issue_count = 0
            high_ratio_count = 0

            total_compressed = 0
            total_uncompressed = 0

            extensions = Counter()
            seen_names = Counter()

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

                if bool(info.flag_bits & 0x1):

                    encrypted_count += 1

                    findings.append(
                        finding(
                            "info",
                            "encryption",
                            "Encrypted archive entry detected.",
                            name if include_entry_names else None,
                        )
                    )

                if extension in ARCHIVE_EXTENSIONS:

                    nested_archive_count += 1

                    findings.append(
                        finding(
                            "info",
                            "nested_archive",
                            "Nested archive detected.",
                            name if include_entry_names else None,
                        )
                    )

                if extension in POTENTIALLY_RISKY_EXTENSIONS:

                    risky_file_count += 1

                    findings.append(
                        finding(
                            "warning",
                            "file_type",
                            (
                                "Potentially executable or script-like "
                                f"file type detected ({extension})."
                            ),
                            name if include_entry_names else None,
                        )
                    )

                if is_suspicious_path(name):

                    suspicious_path_count += 1

                    findings.append(
                        finding(
                            "warning",
                            "path",
                            (
                                "Suspicious archive path detected "
                                "(possible traversal or absolute path)."
                            ),
                            name if include_entry_names else None,
                        )
                    )

                if not timestamp_is_valid(info):

                    metadata_issue_count += 1

                    findings.append(
                        finding(
                            "warning",
                            "metadata",
                            "Invalid or impossible ZIP timestamp detected.",
                            name if include_entry_names else None,
                        )
                    )

                if info.compress_type not in KNOWN_COMPRESSION_METHODS:

                    findings.append(
                        finding(
                            "info",
                            "compression",
                            (
                                "Unknown or unsupported compression "
                                f"method: {info.compress_type}"
                            ),
                            name if include_entry_names else None,
                        )
                    )

                if info.file_size > MAX_SINGLE_UNCOMPRESSED:

                    findings.append(
                        finding(
                            "warning",
                            "size",
                            (
                                "Entry declares a large uncompressed size: "
                                f"{human_bytes(info.file_size)}"
                            ),
                            name if include_entry_names else None,
                        )
                    )

                if info.compress_size > 0:

                    ratio = (
                        info.file_size
                        / info.compress_size
                    )

                    if ratio > MAX_COMPRESSION_RATIO:

                        high_ratio_count += 1

                        findings.append(
                            finding(
                                "warning",
                                "compression_ratio",
                                (
                                    "Unusually high compression ratio "
                                    f"detected ({ratio:.1f}x)."
                                ),
                                name if include_entry_names else None,
                            )
                        )

                elif info.file_size > 0:

                    high_ratio_count += 1

                    findings.append(
                        finding(
                            "warning",
                            "compression_ratio",
                            (
                                "Entry declares uncompressed data "
                                "but zero compressed size."
                            ),
                            name if include_entry_names else None,
                        )
                    )

                header_issues = inspect_local_header(
                    raw_file,
                    info,
                    archive_size,
                )

                for issue in header_issues:

                    metadata_issue_count += 1

                    findings.append(
                        finding(
                            "warning",
                            "metadata",
                            issue,
                            name if include_entry_names else None,
                        )
                    )

            duplicates = [
                name
                for name, count in seen_names.items()
                if count > 1
            ]

            for name in duplicates:

                findings.append(
                    finding(
                        "warning",
                        "duplicate",
                        (
                            "Duplicate archive entry name detected "
                            f"({seen_names[name]} occurrences)."
                        ),
                        name if include_entry_names else None,
                    )
                )

            if total_uncompressed > MAX_TOTAL_UNCOMPRESSED:

                findings.append(
                    finding(
                        "warning",
                        "size",
                        (
                            "Total declared uncompressed size is large: "
                            f"{human_bytes(total_uncompressed)}"
                        ),
                    )
                )

            overall_ratio = None

            if total_compressed > 0:

                overall_ratio = (
                    total_uncompressed
                    / total_compressed
                )

                if overall_ratio > MAX_COMPRESSION_RATIO:

                    findings.append(
                        finding(
                            "warning",
                            "compression_ratio",
                            (
                                "Archive-wide compression ratio is "
                                f"unusually high ({overall_ratio:.1f}x)."
                            ),
                        )
                    )

            report["file_types"] = dict(
                sorted(extensions.items())
            )

            report["summary"] = {
                "entries": len(infos),
                "files": file_count,
                "directories": directory_count,
                "encrypted_entries": encrypted_count,
                "nested_archives": nested_archive_count,
                "potentially_risky_file_types": risky_file_count,
                "suspicious_paths": suspicious_path_count,
                "duplicate_names": len(duplicates),
                "metadata_findings": metadata_issue_count,
                "high_compression_ratio_entries": high_ratio_count,
                "compressed_size": human_bytes(
                    total_compressed
                ),
                "uncompressed_size": human_bytes(
                    total_uncompressed
                ),
                "overall_compression_ratio": (
                    round(overall_ratio, 2)
                    if overall_ratio is not None
                    else None
                ),
                "warnings": sum(
                    1
                    for item in findings
                    if item["severity"] == "warning"
                ),
            }

    return report


def print_report(report: dict) -> None:

    summary = report["summary"]

    print()
    print(f"Before You Unzip v{report['version']}")
    print("=" * 56)

    print(f"Archive:              {report['archive']}")
    print(f"Archive size:         {report['archive_size']}")
    print(f"Entries:              {summary['entries']}")
    print(f"Files:                {summary['files']}")
    print(f"Directories:          {summary['directories']}")
    print(
        f"Uncompressed size:    "
        f"{summary['uncompressed_size']}"
    )

    ratio = summary["overall_compression_ratio"]

    print(
        f"Compression ratio:    "
        f"{ratio}x"
        if ratio is not None
        else "Compression ratio:    n/a"
    )

    print()
    print("Archive-level checks")
    print("-" * 56)

    checks = [
        (
            "Encrypted entries",
            summary["encrypted_entries"],
        ),
        (
            "Nested archives",
            summary["nested_archives"],
        ),
        (
            "Potentially risky file types",
            summary["potentially_risky_file_types"],
        ),
        (
            "Suspicious paths",
            summary["suspicious_paths"],
        ),
        (
            "Duplicate names",
            summary["duplicate_names"],
        ),
        (
            "Metadata findings",
            summary["metadata_findings"],
        ),
        (
            "High compression ratios",
            summary["high_compression_ratio_entries"],
        ),
    ]

    for label, value in checks:

        marker = "!" if value else "✓"

        print(
            f"{marker} {label:<32} {value}"
        )

    print()
    print("File types")
    print("-" * 56)

    if report["file_types"]:

        for extension, count in report["file_types"].items():

            print(
                f"{extension:<12} {count}"
            )

    else:

        print("No file entries found.")

    print()
    print("Findings")
    print("-" * 56)

    if report["findings"]:

        for item in report["findings"]:

            marker = (
                "!"
                if item["severity"] == "warning"
                else "i"
            )

            entry = ""

            if "entry" in item:
                entry = f" [{item['entry']}]"

            print(
                f"{marker} {item['message']}{entry}"
            )

    else:

        print(
            "No obvious archive-level warnings were found."
        )

    print()
    print("Important")
    print("-" * 56)

    print(
        "No files extracted. No files executed."
    )

    print(
        "This is not an antivirus verdict."
    )

    print(
        "Further scanning may still be appropriate."
    )

    print()


def parse_args():

    parser = argparse.ArgumentParser(
        prog="before-you-unzip",
        description=(
            "Inspect a ZIP archive before unpacking it."
        ),
    )

    parser.add_argument(
        "archive",
        type=Path,
        help="Path to the ZIP archive",
    )

    parser.add_argument(
        "--json",
        dest="json_path",
        type=Path,
        help="Write inspection report to JSON",
    )

    parser.add_argument(
        "--public-report",
        action="store_true",
        help=(
            "Hide individual archive entry names "
            "from findings"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )

    return parser.parse_args()


def main() -> int:

    args = parse_args()

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
            "Error: supplied path is not a file.",
            file=sys.stderr,
        )

        return 2

    if not zipfile.is_zipfile(archive_path):

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
        )

    except (
        OSError,
        zipfile.BadZipFile,
        RuntimeError,
    ) as exc:

        print(
            f"Error while inspecting archive: {exc}",
            file=sys.stderr,
        )

        return 1

    print_report(report)

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

        print(
            f"JSON report written to: "
            f"{output_path}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
