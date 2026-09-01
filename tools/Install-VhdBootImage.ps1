# Copyright (c) 2026, Keishin Senzaki. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause-Patent

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $Artifact,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $TargetImage
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$expectedOriginalHash = '6161D63520EB72BD1D5CB99AA9A771CC8B93AD9718DE637B7D2195911DD224EF'

function Get-Sha256 {
    param([Parameter(Mandatory)][string] $LiteralPath)

    $stream = [System.IO.File]::OpenRead($LiteralPath)
    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '')
        } finally {
            $sha256.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

if (-not $Artifact) {
    $Artifact = Join-Path $repo 'artifacts\ventoy_vhdboot_encrypted.img'
}

if (-not (Test-Path -LiteralPath $Artifact -PathType Leaf)) {
    throw "Built image does not exist: $Artifact"
}
if (-not (Test-Path -LiteralPath $TargetImage -PathType Leaf)) {
    throw "Target Ventoy vhdboot image does not exist: $TargetImage"
}

$artifactPath = [System.IO.Path]::GetFullPath($Artifact)
$targetPath = [System.IO.Path]::GetFullPath($TargetImage)
$targetDirectory = Split-Path -Parent $targetPath
$backupPath = Join-Path $targetDirectory 'ventoy_vhdboot.original.img'
$stagingPath = Join-Path $targetDirectory ('.evb-install-' + [guid]::NewGuid().ToString('N') + '.img')
$artifactHash = Get-Sha256 -LiteralPath $artifactPath
$targetHash = Get-Sha256 -LiteralPath $targetPath

if ($targetHash -eq $artifactHash) {
    Write-Host "Already installed: $targetPath"
    return
}

if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
    $backupHash = Get-Sha256 -LiteralPath $backupPath
    if ($backupHash -ne $expectedOriginalHash) {
        throw "Existing backup is not the supported stock image: $backupPath"
    }
} else {
    if ($targetHash -ne $expectedOriginalHash) {
        throw 'Refusing to replace an unknown target without a verified stock-image backup.'
    }

    if ($PSCmdlet.ShouldProcess($backupPath, 'Create immutable stock-image backup')) {
        Copy-Item -LiteralPath $targetPath -Destination $backupPath
        (Get-Item -LiteralPath $backupPath).IsReadOnly = $true
    } elseif (-not $WhatIfPreference) {
        return
    }
}

if ($PSCmdlet.ShouldProcess($targetPath, 'Install encrypted-VHD-capable Ventoy vhdboot image')) {
    Copy-Item -LiteralPath $artifactPath -Destination $stagingPath -Force
    try {
        $stagingHash = Get-Sha256 -LiteralPath $stagingPath
        if ($stagingHash -ne $artifactHash) {
            throw 'Staged image hash does not match the built artifact.'
        }
        Move-Item -LiteralPath $stagingPath -Destination $targetPath -Force
    } finally {
        if (Test-Path -LiteralPath $stagingPath) {
            Remove-Item -LiteralPath $stagingPath -Force
        }
    }
}

if ($WhatIfPreference) {
    Write-Host "Preview only; no files changed. Artifact SHA-256: $artifactHash"
} else {
    Write-Host "Installed: $targetPath"
    Write-Host "Stock backup: $backupPath"
    Write-Host "SHA-256: $artifactHash"
}
