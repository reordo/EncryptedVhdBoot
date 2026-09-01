# Copyright (c) 2026, Keishin Senzaki. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause-Patent

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $SourceImage,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $OutputImage,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $BcdOverride
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$python = Join-Path $repo '.cache\venv\Scripts\python.exe'
$preloader = Join-Path $repo 'artifacts\EncryptedVhdBoot.efi'

if (-not $OutputImage) {
    $OutputImage = Join-Path $repo 'artifacts\ventoy_vhdboot_encrypted.img'
}

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'The local Python environment is missing. Run tools\Initialize-Repository.ps1 first.'
}

if (-not (Test-Path -LiteralPath $preloader -PathType Leaf)) {
    & (Join-Path $PSScriptRoot 'Build-Preloader.cmd')
    if ($LASTEXITCODE -ne 0) {
        throw "Preloader build failed with exit code $LASTEXITCODE."
    }
}

$arguments = @(
    (Join-Path $PSScriptRoot 'build_vhdboot_image.py')
    '--source', $SourceImage
    '--preloader', $preloader
    '--output', $OutputImage
)
if ($BcdOverride) {
    $arguments += @('--bcd-override', $BcdOverride)
}

& $python @arguments

if ($LASTEXITCODE -ne 0) {
    throw "Image build failed with exit code $LASTEXITCODE."
}
