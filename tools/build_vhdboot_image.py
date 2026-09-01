#!/usr/bin/env python3
# Copyright (c) 2026, Keishin Senzaki. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause-Patent

"""Build a local Ventoy vhdboot image containing the EVB UEFI preloader.

The Microsoft and Ventoy files are copied from an upstream source image.
They are never committed to this repository.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import tempfile
import time
import warnings
from pathlib import Path
from unittest import mock

import pycdlib

warnings.filterwarnings(
    "ignore",
    message="pkg_resources is deprecated as an API.*",
    category=UserWarning,
)

from pyfatfs.PyFat import PyFat
from pyfatfs.DosDateTime import DosDateTime
from pyfatfs.PyFatFS import PyFatFS


SUPPORTED_SOURCE_SHA256 = (
    "6161d63520eb72bd1d5cb99aa9a771cc8b93ad9718de637b7d2195911dd224ef"
)
EFI_IMAGE_SIZE = 4 * 1024 * 1024
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUILD_TIMESTAMP = 1788220800  # 2026-09-01 00:00:00 UTC
FAT_BUILD_TIME = DosDateTime(2026, 9, 1, tzinfo=datetime.timezone.utc)

ISO_FILES = {
    "/BOOTMGR": "/BOOTMGR;1",
    "/boot/BCD": "/BOOT/BCD;1",
    "/boot/bootvhd.dll": "/BOOT/BOOTVHD.DLL;1",
    "/boot/etfsboot.com": "/BOOT/ETFSBOOT.COM;1",
}

PROJECT_FILES = {
    PROJECT_ROOT / "README.md": "/EVB/README.MD;1",
    PROJECT_ROOT / "SOURCE.txt": "/EVB/SOURCE.TXT;1",
    PROJECT_ROOT / "LICENSE": "/EVB/LICENSE.TXT;1",
    PROJECT_ROOT / "NOTICE": "/EVB/NOTICE.TXT;1",
    PROJECT_ROOT / "LICENSES" / "BSD-2-Clause-Patent.txt": "/EVB/BSD2PAT.TXT;1",
    PROJECT_ROOT / "LICENSES" / "GPL-3.0.txt": "/EVB/GPL3.TXT;1",
    PROJECT_ROOT / "LICENSES" / "LGPL-3.0.txt": "/EVB/LGPL3.TXT;1",
    PROJECT_ROOT / "LICENSES" / "VeraCrypt.txt": "/EVB/VERACRYP.TXT;1",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def extract_iso_file(iso: pycdlib.PyCdlib, iso_path: str, output: Path) -> None:
    with output.open("wb") as stream:
        iso.get_file_from_iso_fp(stream, iso_path=iso_path)


def create_efi_image(
    original_efi_image: Path,
    preloader: Path,
    output: Path,
) -> None:
    original_fs = PyFatFS(str(original_efi_image), read_only=True)
    try:
        original_boot_manager = original_fs.readbytes("EFI/BOOT/BOOTX64.EFI")
    finally:
        original_fs.close()

    with (
        mock.patch.object(DosDateTime, "now", return_value=FAT_BUILD_TIME),
        mock.patch.object(
            DosDateTime,
            "fromtimestamp",
            return_value=FAT_BUILD_TIME,
        ),
    ):
        output.touch()
        fat = PyFat()
        fat.mkfs(
            str(output),
            PyFat.FAT_TYPE_FAT12,
            size=EFI_IMAGE_SIZE,
            label="EVB EFI",
            volume_id=0x45564231,
            media_type=0xF8,
        )
        fat.close()

        output_fs = PyFatFS(str(output), preserve_case=True)
        try:
            output_fs.makedirs("EFI/BOOT", recreate=True)
            output_fs.writebytes("EFI/BOOT/bootx64.efi", preloader.read_bytes())
            output_fs.writebytes(
                "EFI/BOOT/bootmgfw.original.efi",
                original_boot_manager,
            )
        finally:
            output_fs.close()


def build_iso(
    source: Path,
    preloader: Path,
    output: Path,
    bcd_override: Path | None = None,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="evb-vhdboot-") as temp_name:
        temp = Path(temp_name)
        source_iso = pycdlib.PyCdlib()
        source_iso.open(str(source))
        try:
            source_files: dict[str, Path] = {}
            for source_path, output_path in ISO_FILES.items():
                extracted = temp / output_path.strip("/").replace("/", "_").replace(";1", "")
                extract_iso_file(source_iso, source_path, extracted)
                source_files[output_path] = extracted

            if bcd_override is not None:
                source_files["/BOOT/BCD;1"] = bcd_override

            original_efi_image = temp / "efi-original.img"
            extract_iso_file(source_iso, "/efi.img", original_efi_image)
        finally:
            source_iso.close()

        efi_image = temp / "efi.img"
        create_efi_image(original_efi_image, preloader, efi_image)

        fixed_utc = time.gmtime(BUILD_TIMESTAMP)
        with (
            mock.patch.object(time, "time", return_value=BUILD_TIMESTAMP),
            mock.patch.object(time, "localtime", return_value=fixed_utc),
            mock.patch(
                "pycdlib.dates.utils.gmtoffset_from_tm",
                return_value=0,
            ),
        ):
            result = pycdlib.PyCdlib()
            result.new(
                interchange_level=3,
                sys_ident="LINUX",
                vol_ident="CDROM",
                app_ident_str="EncryptedVhdBoot",
            )

            result.add_directory("/BOOT")
            result.add_directory("/EFI")
            result.add_directory("/EFI/MICROSOFT")
            result.add_directory("/EFI/MICROSOFT/BOOT")
            result.add_directory("/EVB")

            for iso_path, extracted in source_files.items():
                result.add_file(str(extracted), iso_path=iso_path)
            for project_file, iso_path in PROJECT_FILES.items():
                result.add_file(str(project_file), iso_path=iso_path)
            # Ventoy patches /boot/BCD in the in-memory ISO. The original
            # image's UEFI BCD is the same ISO extent under a second directory
            # name, so the patch is visible through both paths. Preserve that
            # aliasing exactly.
            result.add_hard_link(
                iso_old_path="/BOOT/BCD;1",
                iso_new_path="/EFI/MICROSOFT/BOOT/BCD;1",
            )
            result.add_file(str(efi_image), iso_path="/EFI.IMG;1")

            result.add_eltorito(
                "/BOOT/ETFSBOOT.COM;1",
                bootcatfile="/BOOT.CAT;1",
                platform_id=0,
                media_name="noemul",
            )
            result.add_eltorito(
                "/EFI.IMG;1",
                bootcatfile="/BOOT.CAT;1",
                platform_id=0xEF,
                efi=True,
                media_name="noemul",
            )

            try:
                result.write(str(output))
            finally:
                result.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--preloader", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bcd-override", type=Path)
    args = parser.parse_args()

    source = args.source.resolve()
    preloader = args.preloader.resolve()
    output = args.output.resolve()
    bcd_override = args.bcd_override.resolve() if args.bcd_override else None

    if not source.is_file():
        parser.error(f"source image does not exist: {source}")
    if not preloader.is_file():
        parser.error(f"preloader does not exist: {preloader}")
    if bcd_override is not None and not bcd_override.is_file():
        parser.error(f"BCD override does not exist: {bcd_override}")

    actual_hash = sha256(source)
    if actual_hash != SUPPORTED_SOURCE_SHA256:
        parser.error(
            "unsupported source image; expected Win10Based v3.0 SHA-256 "
            f"{SUPPORTED_SOURCE_SHA256}, got {actual_hash}"
        )
    if source == output:
        parser.error("output image must be different from the source image")

    build_iso(source, preloader, output, bcd_override)
    print(f"Built: {output}")
    print(f"SHA-256: {sha256(output)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
