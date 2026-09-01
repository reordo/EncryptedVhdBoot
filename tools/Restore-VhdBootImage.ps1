# Copyright (c) 2026, Keishin Senzaki. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause-Patent

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $TargetImage
)

$ErrorActionPreference = 'Stop'
$expectedOriginalHash = '6161D63520EB72BD1D5CB99AA9A771CC8B93AD9718DE637B7D2195911DD224EF'
$targetPath = [System.IO.Path]::GetFullPath($TargetImage)
$targetDirectory = Split-Path -Parent $targetPath
$backupPath = Join-Path $targetDirectory 'ventoy_vhdboot.original.img'
$stagingPath = Join-Path $targetDirectory ('.evb-restore-' + [guid]::NewGuid().ToString('N') + '.img')

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

if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
    throw "Target Ventoy vhdboot image does not exist: $targetPath"
}
if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
    throw "Stock-image backup does not exist: $backupPath"
}
if ((Get-Sha256 -LiteralPath $backupPath) -ne $expectedOriginalHash) {
    throw "Stock-image backup failed hash validation: $backupPath"
}
if ((Get-Sha256 -LiteralPath $targetPath) -eq $expectedOriginalHash) {
    Write-Host "Stock image is already active: $targetPath"
    return
}

if ($PSCmdlet.ShouldProcess($targetPath, 'Restore stock Ventoy vhdboot image')) {
    Copy-Item -LiteralPath $backupPath -Destination $stagingPath -Force
    try {
        (Get-Item -LiteralPath $stagingPath).IsReadOnly = $false
        if ((Get-Sha256 -LiteralPath $stagingPath) -ne $expectedOriginalHash) {
            throw 'Staged stock image failed hash validation.'
        }
        Move-Item -LiteralPath $stagingPath -Destination $targetPath -Force
    } finally {
        if (Test-Path -LiteralPath $stagingPath) {
            Remove-Item -LiteralPath $stagingPath -Force
        }
    }
    Write-Host "Restored stock image: $targetPath"
    Write-Host "Backup retained: $backupPath"
}
