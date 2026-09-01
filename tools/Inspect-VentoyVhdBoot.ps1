# Copyright (c) 2026, Keishin Senzaki. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause-Patent

param(
    [Parameter(Mandatory = $true)]
    [string]$ImagePath,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,

    [string]$SevenZip,
    [string]$LlvmReadObj
)

$ErrorActionPreference = 'Stop'

if (-not $SevenZip) {
    $SevenZip = (Get-Command 7z.exe -ErrorAction SilentlyContinue).Source
}
if (-not $LlvmReadObj) {
    $LlvmReadObj = (Get-Command llvm-readobj.exe -ErrorAction SilentlyContinue).Source
}

foreach ($tool in @($SevenZip, $LlvmReadObj)) {
    if (-not $tool -or -not (Test-Path -LiteralPath $tool)) {
        throw "Required tool was not found: $tool"
    }
}

$outer = Join-Path $OutputDirectory 'outer'
$efi = Join-Path $OutputDirectory 'efi'
New-Item -ItemType Directory -Path $outer, $efi -Force | Out-Null

& $SevenZip x -y "-o$outer" $ImagePath | Out-Null
$efiImage = Join-Path $outer 'efi.img'
if (-not (Test-Path -LiteralPath $efiImage)) {
    throw 'efi.img was not found in the Ventoy VHD boot image.'
}

# 7-Zip reports the intentionally short FAT image as truncated but extracts its
# complete boot file. Accept that diagnostic and verify the output explicitly.
& $SevenZip x -y "-o$efi" $efiImage | Out-Null
$bootManager = Join-Path $efi 'EFI\BOOT\bootx64.efi'
if (-not (Test-Path -LiteralPath $bootManager)) {
    throw 'EFI/BOOT/bootx64.efi was not extracted.'
}

$legacyDll = Join-Path $outer 'boot\bootvhd.dll'

[pscustomobject]@{
    ImageSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $ImagePath).Hash
    UefiBootManager = $bootManager
    UefiBootManagerVersion = (Get-Item -LiteralPath $bootManager).VersionInfo.FileVersion
    LegacyBootVhdDll = if (Test-Path -LiteralPath $legacyDll) { $legacyDll } else { $null }
    LegacyBootVhdArchitecture = if (Test-Path -LiteralPath $legacyDll) {
        (& $LlvmReadObj --file-headers $legacyDll | Select-String '^Arch:').Line
    } else {
        $null
    }
}

& $LlvmReadObj --file-headers --coff-debug-directory $bootManager
