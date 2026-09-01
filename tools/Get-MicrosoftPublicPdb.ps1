# Copyright (c) 2026, Keishin Senzaki. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause-Patent

param(
    [Parameter(Mandatory = $true)]
    [string]$ImagePath,

    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,

    [string]$LlvmReadObj
)

$ErrorActionPreference = 'Stop'

if (-not $LlvmReadObj) {
    $LlvmReadObj = (Get-Command llvm-readobj.exe -ErrorAction SilentlyContinue).Source
}

if (-not $LlvmReadObj -or -not (Test-Path -LiteralPath $LlvmReadObj)) {
    throw 'llvm-readobj was not found. Add LLVM to PATH or pass -LlvmReadObj.'
}

$debugText = & $LlvmReadObj --coff-debug-directory $ImagePath 2>&1 | Out-String
$nameMatch = [regex]::Match($debugText, 'PDBFileName:\s*([^\r\n]+)')
$guidMatch = [regex]::Match($debugText, 'PDBGUID:\s*\{([^}]+)\}')
$ageMatch = [regex]::Match($debugText, 'PDBAge:\s*(\d+)')

if (-not ($nameMatch.Success -and $guidMatch.Success -and $ageMatch.Success)) {
    throw 'The CodeView PDB identity could not be parsed from the image.'
}

$pdbName = $nameMatch.Groups[1].Value.Trim()
$guid = $guidMatch.Groups[1].Value.Replace('-', '').ToUpperInvariant()
$age = [int]$ageMatch.Groups[1].Value
$symbolKey = "$guid$age"
$destinationDirectory = Join-Path $OutputRoot "$pdbName\$symbolKey"
$destination = Join-Path $destinationDirectory $pdbName
$uri = "https://msdl.microsoft.com/download/symbols/$pdbName/$symbolKey/$pdbName"

New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
if (-not (Test-Path -LiteralPath $destination)) {
    Invoke-WebRequest -Uri $uri -OutFile $destination
}

[pscustomobject]@{
    Image = (Resolve-Path -LiteralPath $ImagePath).Path
    Pdb = $destination
    Guid = $guidMatch.Groups[1].Value
    Age = $age
    SymbolServerUri = $uri
}
