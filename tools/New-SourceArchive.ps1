# Copyright (c) 2026, Keishin Senzaki. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause-Patent

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
param(
    [Parameter()]
    [ValidatePattern('^[0-9A-Za-z][0-9A-Za-z._-]*$')]
    [string] $Version = '1.0.0',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $OutputArchive,

    [switch] $Force
)

$ErrorActionPreference = 'Stop'
$repo = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$packageName = "EncryptedVhdBoot-v$Version-source"

if (-not $OutputArchive) {
    $OutputArchive = Join-Path $repo "artifacts\$packageName.zip"
}
$OutputArchive = [System.IO.Path]::GetFullPath($OutputArchive)

$components = @(
    @{ Path = 'third_party/VeraCrypt'; Parent = '.' },
    @{ Path = 'third_party/VeraCrypt-DCS'; Parent = '.' },
    @{ Path = 'third_party/edk2'; Parent = '.' },
    @{
        Path = 'BaseTools/Source/C/BrotliCompress/brotli'
        Parent = 'third_party/edk2'
        Destination = 'third_party/edk2/BaseTools/Source/C/BrotliCompress/brotli'
    },
    @{
        Path = 'MdePkg/Library/MipiSysTLib/mipisyst'
        Parent = 'third_party/edk2'
        Destination = 'third_party/edk2/MdePkg/Library/MipiSysTLib/mipisyst'
    }
)

function Invoke-Git {
    param(
        [Parameter(Mandatory)][string] $WorkingTree,
        [Parameter(Mandatory)][string[]] $Arguments
    )

    & git -C $WorkingTree @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "git failed in '$WorkingTree': git $($Arguments -join ' ')"
    }
}

Invoke-Git -WorkingTree $repo -Arguments @('rev-parse', '--is-inside-work-tree') | Out-Null
$rootCommit = (& git -C $repo rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'Cannot resolve the repository commit.'
}

$manifest = [System.Collections.Generic.List[string]]::new()
$manifest.Add("EncryptedVhdBoot $rootCommit")

foreach ($component in $components) {
    $parentPath = if ($component.Parent -eq '.') {
        $repo
    } else {
        Join-Path $repo $component.Parent
    }
    $childPath = Join-Path $parentPath $component.Path
    if (-not (Test-Path -LiteralPath (Join-Path $childPath '.git'))) {
        throw "Submodule is not initialized: $childPath"
    }

    $expected = (& git -C $parentPath rev-parse "HEAD:$($component.Path)").Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot resolve the recorded commit for $($component.Path)."
    }
    $actual = (& git -C $childPath rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Cannot resolve the checked-out commit for $childPath."
    }
    if ($actual -ne $expected) {
        throw "Submodule checkout mismatch for ${childPath}: expected $expected, found $actual."
    }

    $destination = if ($component.Destination) {
        $component.Destination
    } elseif ($component.Parent -eq '.') {
        $component.Path
    } else {
        "$($component.Parent)/$($component.Path)"
    }
    $manifest.Add("$destination $actual")
}

if ((Test-Path -LiteralPath $OutputArchive) -and -not $Force) {
    throw "Output archive already exists: $OutputArchive (use -Force to replace it)"
}
if (-not $PSCmdlet.ShouldProcess($OutputArchive, 'Create complete source archive')) {
    return
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("evb-source-" + [guid]::NewGuid().ToString('N'))
$archiveDirectory = Split-Path -Parent $OutputArchive

try {
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $archiveDirectory -Force | Out-Null

    $inputArchives = [System.Collections.Generic.List[string]]::new()
    $rootZip = Join-Path $tempRoot 'root.zip'
    Invoke-Git -WorkingTree $repo -Arguments @(
        'archive', '--format=zip', "--prefix=$packageName/", '-o', $rootZip, 'HEAD'
    )
    $inputArchives.Add($rootZip)

    foreach ($component in $components) {
        $parentPath = if ($component.Parent -eq '.') {
            $repo
        } else {
            Join-Path $repo $component.Parent
        }
        $childPath = Join-Path $parentPath $component.Path
        $destination = if ($component.Destination) {
            $component.Destination
        } elseif ($component.Parent -eq '.') {
            $component.Path
        } else {
            "$($component.Parent)/$($component.Path)"
        }
        $componentZip = Join-Path $tempRoot (([guid]::NewGuid().ToString('N')) + '.zip')
        $prefix = "$packageName/$destination/"
        Invoke-Git -WorkingTree $childPath -Arguments @(
            'archive', '--format=zip', "--prefix=$prefix", '-o', $componentZip, 'HEAD'
        )
        $inputArchives.Add($componentZip)
    }

    if (Test-Path -LiteralPath $OutputArchive) {
        Remove-Item -LiteralPath $OutputArchive -Force
    }

    $outputStream = [System.IO.File]::Open(
        $OutputArchive,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None
    )
    try {
        $outputZip = [System.IO.Compression.ZipArchive]::new(
            $outputStream,
            [System.IO.Compression.ZipArchiveMode]::Create,
            $true
        )
        try {
            $entryNames = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::Ordinal
            )
            foreach ($inputArchive in $inputArchives) {
                $inputStream = [System.IO.File]::OpenRead($inputArchive)
                try {
                    $inputZip = [System.IO.Compression.ZipArchive]::new(
                        $inputStream,
                        [System.IO.Compression.ZipArchiveMode]::Read,
                        $false
                    )
                    try {
                        foreach ($inputEntry in $inputZip.Entries) {
                            if (-not $entryNames.Add($inputEntry.FullName)) {
                                continue
                            }

                            $outputEntry = $outputZip.CreateEntry(
                                $inputEntry.FullName,
                                [System.IO.Compression.CompressionLevel]::Optimal
                            )
                            $outputEntry.LastWriteTime = $inputEntry.LastWriteTime
                            if ($inputEntry.Length -ne 0) {
                                $source = $inputEntry.Open()
                                $destinationStream = $outputEntry.Open()
                                try {
                                    $source.CopyTo($destinationStream)
                                } finally {
                                    $destinationStream.Dispose()
                                    $source.Dispose()
                                }
                            }
                        }
                    } finally {
                        $inputZip.Dispose()
                    }
                } finally {
                    $inputStream.Dispose()
                }
            }

            $manifestEntry = $outputZip.CreateEntry(
                "$packageName/SOURCE-MANIFEST.txt",
                [System.IO.Compression.CompressionLevel]::Optimal
            )
            $manifestStream = $manifestEntry.Open()
            $writer = [System.IO.StreamWriter]::new(
                $manifestStream,
                [System.Text.UTF8Encoding]::new($false)
            )
            try {
                foreach ($line in $manifest) {
                    $writer.WriteLine($line)
                }
            } finally {
                $writer.Dispose()
            }
        } finally {
            $outputZip.Dispose()
        }
    } finally {
        $outputStream.Dispose()
    }
} finally {
    if (Test-Path -LiteralPath $tempRoot) {
        $resolvedTemp = [System.IO.Path]::GetFullPath($tempRoot)
        $expectedParent = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if ($resolvedTemp.StartsWith($expectedParent, [System.StringComparison]::OrdinalIgnoreCase) -and
            ([System.IO.Path]::GetFileName($resolvedTemp) -like 'evb-source-*')) {
            Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
        }
    }
}

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $OutputArchive).Hash.ToLowerInvariant()
Write-Host "Created: $OutputArchive"
Write-Host "SHA-256: $hash"
