# Copyright (c) 2026, Keishin Senzaki. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause-Patent

[CmdletBinding()]
param(
    [string] $PythonCommand
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

function Test-PythonInterpreter {
    param(
        [Parameter(Mandatory)]
        [string] $FilePath,

        [string[]] $Arguments = @()
    )

    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'SilentlyContinue'
        $testArguments = @($Arguments) + @(
            '-c',
            'import sys; raise SystemExit(sys.version_info < (3, 10))'
        )
        & $FilePath @testArguments *> $null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    } finally {
        $ErrorActionPreference = $savedPreference
    }
}

$edk2 = Join-Path $repo 'third_party\edk2'
$gitMetadata = Join-Path $repo '.git'
if (Test-Path -LiteralPath $gitMetadata) {
    & git -C $repo submodule update --init
    if ($LASTEXITCODE -ne 0) {
        throw "Submodule initialization failed with exit code $LASTEXITCODE."
    }

    & git -C $edk2 submodule update --init -- `
        'BaseTools/Source/C/BrotliCompress/brotli' `
        'MdePkg/Library/MipiSysTLib/mipisyst'
    if ($LASTEXITCODE -ne 0) {
        throw "Required EDK2 submodule initialization failed with exit code $LASTEXITCODE."
    }
} else {
    $archiveInputs = @(
        'third_party\edk2\edksetup.bat',
        'third_party\VeraCrypt\src\Common\Crypto.c',
        'third_party\VeraCrypt-DCS\DcsPkg.dec',
        'third_party\VeraCrypt-DCS\Library\VeraCryptLib\mklinks_src.bat',
        'third_party\edk2\BaseTools\Source\C\BrotliCompress\brotli\c\common\constants.c',
        'third_party\edk2\MdePkg\Library\MipiSysTLib\mipisyst\library\include\mipi_syst.h.in'
    )
    foreach ($relativePath in $archiveInputs) {
        if (-not (Test-Path -LiteralPath (Join-Path $repo $relativePath) -PathType Leaf)) {
            throw "Required source-archive input is missing: $relativePath"
        }
    }

    Write-Host 'Complete source archive detected; Git submodule initialization is not required.'
}

$pythonArguments = @()
if (-not $PythonCommand) {
    foreach ($name in @('py.exe', 'python3.exe', 'python.exe')) {
        $candidate = (Get-Command $name -ErrorAction SilentlyContinue).Source
        if (-not $candidate) {
            continue
        }

        $candidateArguments = if ($name -eq 'py.exe') { @('-3') } else { @() }
        if (Test-PythonInterpreter -FilePath $candidate -Arguments $candidateArguments) {
            $PythonCommand = $candidate
            $pythonArguments = $candidateArguments
            break
        }
    }
} else {
    if (-not (Test-PythonInterpreter -FilePath $PythonCommand)) {
        throw "PythonCommand is not a usable Python 3.10+ interpreter: $PythonCommand"
    }
}

if (-not $PythonCommand) {
    throw 'Python 3.10 or later was not found. Add it to PATH or pass -PythonCommand.'
}

$venv = Join-Path $repo '.cache\venv'
$venvPython = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    $venvArguments = @($pythonArguments) + @('-m', 'venv', $venv)
    & $PythonCommand @venvArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Virtual environment creation failed with exit code $LASTEXITCODE."
    }
}

& $venvPython -m pip install --disable-pip-version-check --require-hashes -r (Join-Path $repo 'requirements.txt')
if ($LASTEXITCODE -ne 0) {
    throw "Python dependency installation failed with exit code $LASTEXITCODE."
}

Write-Host 'Repository initialized.'
